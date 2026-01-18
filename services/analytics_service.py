import logging
from typing import Dict, Any, List
from datetime import datetime, timedelta
from services.vulnerability_service import VulnerabilityService
from services.operator_service import OperatorService
from config import Config

logger = logging.getLogger(__name__)


class AnalyticsService:
    """Сервис для управления аналитикой и статистикой"""

    def __init__(self):
        self.vuln_service = VulnerabilityService()
        self.operator_service = OperatorService()
        self._cached_analytics = None
        self._cache_timestamp = None
        self._cache_duration = timedelta(minutes=1)  # Кэшируем на 1 минуту

    def get_analytics_data(self, force_refresh: bool = False) -> Dict[str, Any]:
        """Получает данные для аналитики с кэшированием"""
        if not force_refresh and self._is_cache_valid():
            return self._cached_analytics

        try:
            # Для legacy схемы: нельзя грузить 100k+ строк в память — считаем агрегаты SQL-ом
            if Config.USE_LEGACY_SCHEMA:
                analytics_data = self._calculate_analytics_legacy_sql()
            else:
                vulnerabilities = self.vuln_service.get_all_vulnerabilities_unlimited()
                operators = self.operator_service.get_all_operators()
                analytics_data = self._calculate_analytics(vulnerabilities, operators)

            # Обновляем кэш
            self._cached_analytics = analytics_data
            self._cache_timestamp = datetime.now()

            logger.info("📊 Analytics data updated")
            return analytics_data

        except Exception as e:
            logger.error(f"Error calculating analytics: {e}")
            return self._get_default_analytics()

    def _calculate_analytics_legacy_sql(self) -> Dict[str, Any]:
        """Аналитика через SQL агрегаты (legacy schema)."""
        try:
            from models.database import DatabaseManager
            db = DatabaseManager()

            total = db.execute_query("SELECT COUNT(*) FROM turn WHERE cve IS NOT NULL AND cve != ''")
            total_vulnerabilities = int(total[0][0]) if total else 0

            # severity via CVSS ranges
            q_sev = db.execute_query(
                """
                SELECT
                  SUM(CASE WHEN cvss >= 9 THEN 1 ELSE 0 END) AS critical,
                  SUM(CASE WHEN cvss >= 7 AND cvss < 9 THEN 1 ELSE 0 END) AS high,
                  SUM(CASE WHEN cvss >= 4 AND cvss < 7 THEN 1 ELSE 0 END) AS medium,
                  SUM(CASE WHEN cvss < 4 THEN 1 ELSE 0 END) AS low
                FROM turn
                WHERE cve IS NOT NULL AND cve != ''
                """
            )
            sev_row = q_sev[0] if q_sev else (0, 0, 0, 0)
            severity_counts = {
                "critical": int(sev_row[0] or 0),
                "high": int(sev_row[1] or 0),
                "medium": int(sev_row[2] or 0),
                "low": int(sev_row[3] or 0),
            }

            q_status = db.execute_query(
                """
                SELECT
                  SUM(CASE WHEN status = TRUE THEN 1 ELSE 0 END) AS new_cnt,
                  SUM(CASE WHEN status = FALSE THEN 1 ELSE 0 END) AS completed_cnt
                FROM turn
                WHERE cve IS NOT NULL AND cve != ''
                """
            )
            st_row = q_status[0] if q_status else (0, 0)

            # in_progress approximated by active assignments
            q_in = db.execute_query("SELECT COUNT(DISTINCT cve) FROM actids WHERE active = TRUE")
            in_progress = int(q_in[0][0]) if q_in else 0

            status_counts = {
                "new": int(st_row[0] or 0),
                "in_progress": in_progress,
                "completed": int(st_row[1] or 0),
                "approved": 0,
            }

            # cvss distribution
            q_cvss = db.execute_query(
                """
                SELECT
                  SUM(CASE WHEN cvss >= 0 AND cvss < 2 THEN 1 ELSE 0 END) AS b0,
                  SUM(CASE WHEN cvss >= 2 AND cvss < 4 THEN 1 ELSE 0 END) AS b1,
                  SUM(CASE WHEN cvss >= 4 AND cvss < 6 THEN 1 ELSE 0 END) AS b2,
                  SUM(CASE WHEN cvss >= 6 AND cvss < 8 THEN 1 ELSE 0 END) AS b3,
                  SUM(CASE WHEN cvss >= 8 THEN 1 ELSE 0 END) AS b4
                FROM turn
                WHERE cve IS NOT NULL AND cve != ''
                """
            )
            c_row = q_cvss[0] if q_cvss else (0, 0, 0, 0, 0)
            cvss_distribution = {
                "0-2": int(c_row[0] or 0),
                "2-4": int(c_row[1] or 0),
                "4-6": int(c_row[2] or 0),
                "6-8": int(c_row[3] or 0),
                "8-10": int(c_row[4] or 0),
            }

            risk_levels = {
                "critical": severity_counts["critical"],
                "high": severity_counts["high"],
                "medium": severity_counts["medium"],
                "low": severity_counts["low"],
            }

            # operator stats (top 50)
            q_ops = db.execute_query(
                """
                SELECT oper, COUNT(*) AS cnt
                FROM actids
                WHERE active = TRUE
                GROUP BY oper
                ORDER BY cnt DESC
                LIMIT 50
                """
            )
            operator_stats = [
                {
                    "name": str(r[0]),
                    "total_assigned": int(r[1] or 0),
                    "active_count": int(r[1] or 0),
                    "completed_count": 0,
                    "completion_rate": 0,
                    "metric": 0,
                }
                for r in (q_ops or [])
            ]

            completed_vulnerabilities = status_counts["completed"] + status_counts["approved"]
            active_operators = len(operator_stats)

            return {
                "severity_counts": severity_counts,
                "status_counts": status_counts,
                "category_counts": {},
                "cvss_distribution": cvss_distribution,
                "risk_levels": risk_levels,
                "operator_stats": operator_stats,
                "total_vulnerabilities": total_vulnerabilities,
                "active_operators": active_operators,
                "completed_vulnerabilities": completed_vulnerabilities,
                "avg_performance": 0,
                "trends": {},
                "last_updated": datetime.now().isoformat(),
            }
        except Exception as e:
            logger.error(f"Error calculating legacy analytics (SQL): {e}", exc_info=True)
            return self._get_default_analytics()

    def _is_cache_valid(self) -> bool:
        """Проверяет валидность кэша"""
        if self._cached_analytics is None or self._cache_timestamp is None:
            return False

        return (datetime.now() - self._cache_timestamp) < self._cache_duration

    def _calculate_analytics(self, vulnerabilities: List, operators: List) -> Dict[str, Any]:
        """Рассчитывает аналитику на основе текущих данных"""
        # Статистика по уровням риска
        severity_counts = {
            'critical': len([v for v in vulnerabilities if v.severity == 'critical']),
            'high': len([v for v in vulnerabilities if v.severity == 'high']),
            'medium': len([v for v in vulnerabilities if v.severity == 'medium']),
            'low': len([v for v in vulnerabilities if v.severity == 'low'])
        }

        # Статистика по статусам
        status_counts = {
            'new': len([v for v in vulnerabilities if v.status == 'new']),
            'in_progress': len([v for v in vulnerabilities if v.status == 'in_progress']),
            'completed': len([v for v in vulnerabilities if v.status == 'completed']),
            'approved': len([v for v in vulnerabilities if v.status == 'approved'])
        }

        # Статистика по категориям
        category_counts = {}
        for vuln in vulnerabilities:
            category = vuln.category or 'other'
            category_counts[category] = category_counts.get(category, 0) + 1

        # Статистика по CVSS (для графиков риска)
        cvss_distribution = {'0-2': 0, '2-4': 0, '4-6': 0, '6-8': 0, '8-10': 0}
        risk_levels = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
        
        for vuln in vulnerabilities:
            # Распределение по CVSS
            try:
                cvss_score = float(vuln.cvss_score) if vuln.cvss_score else 0.0
                if 0 <= cvss_score < 2:
                    cvss_distribution['0-2'] += 1
                elif 2 <= cvss_score < 4:
                    cvss_distribution['2-4'] += 1
                elif 4 <= cvss_score < 6:
                    cvss_distribution['4-6'] += 1
                elif 6 <= cvss_score < 8:
                    cvss_distribution['6-8'] += 1
                elif 8 <= cvss_score <= 10:
                    cvss_distribution['8-10'] += 1
            except (ValueError, TypeError):
                cvss_distribution['0-2'] += 1
            
            # Распределение по уровням риска
            risk_level = vuln.risk_level or 'medium'
            if risk_level in risk_levels:
                risk_levels[risk_level] += 1
            else:
                risk_levels['medium'] += 1

        # Статистика операторов
        operator_stats = []
        for operator in operators:
            assigned_vulns = operator.assigned_vulnerabilities
            active_vulns = [v for v in assigned_vulns if v.status != 'completed']
            completed_vulns = [v for v in assigned_vulns if v.status == 'completed']

            operator_stats.append({
                'name': operator.name,
                'total_assigned': len(assigned_vulns),
                'active_count': len(active_vulns),
                'completed_count': len(completed_vulns),
                'completion_rate': (len(completed_vulns) / len(assigned_vulns) * 100) if assigned_vulns else 0,
                'metric': operator.current_metric
            })

        # Общая статистика
        total_vulnerabilities = len(vulnerabilities)
        active_operators = len(operators)
        completed_vulnerabilities = status_counts['completed'] + status_counts['approved']

        # Средняя производительность (исключаем операторов без уязвимостей)
        operators_with_vulns = [op for op in operators if op.assigned_vulnerabilities]
        avg_performance = (
            sum(op.current_metric for op in operators_with_vulns) / len(operators_with_vulns)
            if operators_with_vulns else 0
        )

        # Тенденции (упрощенная версия)
        trends = self._calculate_trends(vulnerabilities)

        return {
            'severity_counts': severity_counts,
            'status_counts': status_counts,
            'category_counts': category_counts,
            'cvss_distribution': cvss_distribution,
            'risk_levels': risk_levels,
            'operator_stats': operator_stats,
            'total_vulnerabilities': total_vulnerabilities,
            'active_operators': active_operators,
            'completed_vulnerabilities': completed_vulnerabilities,
            'avg_performance': avg_performance,
            'trends': trends,
            'last_updated': datetime.now().isoformat()
        }

    def _calculate_trends(self, vulnerabilities: List) -> Dict[str, Any]:
        """Рассчитывает тренды (упрощенная версия)"""
        # В реальной системе здесь была бы логика сравнения с предыдущими данными
        critical_count = len([v for v in vulnerabilities if v.severity == 'critical'])
        high_count = len([v for v in vulnerabilities if v.severity == 'high'])

        return {
            'critical_trend': 'up' if critical_count > 5 else 'stable',
            'high_trend': 'up' if high_count > 10 else 'stable',
            'completion_trend': 'improving',
            'risk_trend': 'increasing' if critical_count + high_count > 15 else 'stable'
        }

    def _get_default_analytics(self) -> Dict[str, Any]:
        """Возвращает аналитику по умолчанию"""
        return {
            'severity_counts': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
            'status_counts': {'new': 0, 'in_progress': 0, 'completed': 0, 'approved': 0},
            'category_counts': {},
            'cvss_distribution': {'0-2': 0, '2-4': 0, '4-6': 0, '6-8': 0, '8-10': 0},
            'risk_levels': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
            'operator_stats': [],
            'total_vulnerabilities': 0,
            'active_operators': 0,
            'completed_vulnerabilities': 0,
            'avg_performance': 0,
            'trends': {},
            'last_updated': datetime.now().isoformat()
        }

    def invalidate_cache(self):
        """Инвалидирует кэш аналитики"""
        self._cached_analytics = None
        self._cache_timestamp = None
        logger.info("🔄 Analytics cache invalidated")


# Глобальный экземпляр сервиса аналитики
analytics_service = AnalyticsService()