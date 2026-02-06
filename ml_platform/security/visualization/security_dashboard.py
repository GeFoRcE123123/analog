"""
Визуализация и дашборды для анализа безопасности
"""

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import pandas as pd
from typing import List, Dict, Any, Optional
from pathlib import Path
from datetime import datetime

from ml_platform.core.logger import PlatformLogger
from ml_platform.security.cve_passport import CVEPassport
from ml_platform.security.risk_engine import RiskCalculation, Asset


class SecurityVisualizer:
    """Визуализатор данных безопасности"""
    
    def __init__(self, output_dir: str = "/home/user/projects/security_reports"):
        """
        Инициализация визуализатора
        
        Args:
            output_dir: Директория для сохранения графиков
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.logger = PlatformLogger.get_logger()
        sns.set_style("whitegrid")
    
    def plot_risk_heatmap(
        self,
        risk_calculations: List[RiskCalculation],
        assets: List[Asset],
        save_path: Optional[str] = None
    ) -> str:
        """
        Построение тепловой карты рисков
        
        Args:
            risk_calculations: Список расчетов рисков
            assets: Список активов
            save_path: Путь для сохранения
            
        Returns:
            Путь к сохраненному файлу
        """
        # Подготовка данных
        asset_dict = {asset.asset_id: asset.name for asset in assets}
        
        data = []
        for calc in risk_calculations:
            data.append({
                "Asset": asset_dict.get(calc.asset_id, calc.asset_id),
                "CVE": calc.cve_id,
                "Risk Score": calc.adjusted_risk_score,
                "Risk Level": calc.risk_level
            })
        
        df = pd.DataFrame(data)
        
        # Создание pivot table
        pivot = df.pivot_table(
            values="Risk Score",
            index="Asset",
            columns="CVE",
            aggfunc="max",
            fill_value=0.0
        )
        
        # Построение heatmap
        fig, ax = plt.subplots(figsize=(max(12, len(pivot.columns) * 0.5), max(8, len(pivot) * 0.3)))
        
        sns.heatmap(
            pivot,
            annot=True,
            fmt=".2f",
            cmap="RdYlGn_r",
            vmin=0,
            vmax=1,
            cbar_kws={"label": "Risk Score"},
            ax=ax
        )
        
        ax.set_title("Risk Heatmap: Assets vs CVEs", fontsize=16, fontweight="bold")
        ax.set_xlabel("CVE", fontsize=12)
        ax.set_ylabel("Asset", fontsize=12)
        
        plt.tight_layout()
        
        if save_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            save_path = self.output_dir / f"risk_heatmap_{timestamp}.png"
        else:
            save_path = Path(save_path)
        
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        self.logger.info(f"Risk heatmap сохранена: {save_path}")
        
        return str(save_path)
    
    def plot_severity_distribution(
        self,
        passports: List[CVEPassport],
        save_path: Optional[str] = None
    ) -> str:
        """
        Распределение уязвимостей по критичности
        
        Args:
            passports: Список паспортов CVE
            save_path: Путь для сохранения
            
        Returns:
            Путь к сохраненному файлу
        """
        severities = [p.get_severity().value for p in passports]
        
        severity_counts = pd.Series(severities).value_counts()
        
        fig, ax = plt.subplots(figsize=(10, 6))
        
        colors = {
            "Critical": "#d32f2f",
            "High": "#f57c00",
            "Medium": "#fbc02d",
            "Low": "#388e3c",
            "None": "#9e9e9e"
        }
        
        bars = ax.bar(
            severity_counts.index,
            severity_counts.values,
            color=[colors.get(s, "#9e9e9e") for s in severity_counts.index]
        )
        
        # Добавление значений на столбцы
        for bar in bars:
            height = bar.get_height()
            ax.text(
                bar.get_x() + bar.get_width()/2., height,
                f'{int(height)}',
                ha='center', va='bottom'
            )
        
        ax.set_xlabel("Severity Level", fontsize=12)
        ax.set_ylabel("Count", fontsize=12)
        ax.set_title("Distribution of Vulnerabilities by Severity", fontsize=14, fontweight="bold")
        ax.grid(True, alpha=0.3, axis='y')
        
        plt.tight_layout()
        
        if save_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            save_path = self.output_dir / f"severity_distribution_{timestamp}.png"
        else:
            save_path = Path(save_path)
        
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        self.logger.info(f"Severity distribution сохранена: {save_path}")
        
        return str(save_path)
    
    def plot_cvss_timeline(
        self,
        passports: List[CVEPassport],
        save_path: Optional[str] = None
    ) -> str:
        """
        Временная линия CVSS scores
        
        Args:
            passports: Список паспортов CVE
            save_path: Путь для сохранения
            
        Returns:
            Путь к сохраненному файлу
        """
        data = []
        for p in passports:
            if p.published_date and p.scoring.cvss_v3:
                data.append({
                    "Date": p.published_date,
                    "CVSS Score": p.scoring.cvss_v3.get("base_score", 0),
                    "Severity": p.get_severity().value
                })
        
        if not data:
            self.logger.warning("Нет данных для временной линии")
            return ""
        
        df = pd.DataFrame(data)
        df = df.sort_values("Date")
        
        fig, ax = plt.subplots(figsize=(14, 6))
        
        # Scatter plot с цветом по severity
        severity_colors = {
            "Critical": "#d32f2f",
            "High": "#f57c00",
            "Medium": "#fbc02d",
            "Low": "#388e3c"
        }
        
        for severity in df["Severity"].unique():
            subset = df[df["Severity"] == severity]
            ax.scatter(
                subset["Date"],
                subset["CVSS Score"],
                label=severity,
                color=severity_colors.get(severity, "#9e9e9e"),
                alpha=0.6,
                s=50
            )
        
        # Moving average
        df["MA"] = df["CVSS Score"].rolling(window=30, min_periods=1).mean()
        ax.plot(df["Date"], df["MA"], color="blue", linewidth=2, label="30-day MA", alpha=0.7)
        
        ax.set_xlabel("Date", fontsize=12)
        ax.set_ylabel("CVSS Score", fontsize=12)
        ax.set_title("CVSS Score Timeline", fontsize=14, fontweight="bold")
        ax.legend()
        ax.grid(True, alpha=0.3)
        
        plt.xticks(rotation=45)
        plt.tight_layout()
        
        if save_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            save_path = self.output_dir / f"cvss_timeline_{timestamp}.png"
        else:
            save_path = Path(save_path)
        
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        self.logger.info(f"CVSS timeline сохранена: {save_path}")
        
        return str(save_path)
    
    def plot_risk_distribution_by_asset(
        self,
        risk_calculations: List[RiskCalculation],
        assets: List[Asset],
        top_n: int = 20,
        save_path: Optional[str] = None
    ) -> str:
        """
        Распределение рисков по активам
        
        Args:
            risk_calculations: Список расчетов рисков
            assets: Список активов
            top_n: Количество топ активов для отображения
            save_path: Путь для сохранения
            
        Returns:
            Путь к сохраненному файлу
        """
        asset_dict = {asset.asset_id: asset for asset in assets}
        
        # Агрегация рисков по активам
        asset_risks = {}
        for calc in risk_calculations:
            asset_id = calc.asset_id
            if asset_id not in asset_risks:
                asset_risks[asset_id] = []
            asset_risks[asset_id].append(calc.adjusted_risk_score)
        
        # Вычисление максимального риска для каждого актива
        asset_max_risks = {
            asset_id: max(risks)
            for asset_id, risks in asset_risks.items()
        }
        
        # Сортировка и выбор топ-N
        sorted_assets = sorted(
            asset_max_risks.items(),
            key=lambda x: x[1],
            reverse=True
        )[:top_n]
        
        asset_names = [asset_dict.get(aid, Asset(aid, aid, "", 0.0, 0.0, [])).name for aid, _ in sorted_assets]
        risk_scores = [score for _, score in sorted_assets]
        
        fig, ax = plt.subplots(figsize=(12, max(8, len(asset_names) * 0.4)))
        
        colors = ['#d32f2f' if s >= 0.7 else '#f57c00' if s >= 0.5 else '#fbc02d' if s >= 0.3 else '#388e3c' for s in risk_scores]
        
        bars = ax.barh(asset_names, risk_scores, color=colors)
        
        # Добавление значений
        for i, (bar, score) in enumerate(zip(bars, risk_scores)):
            ax.text(
                score, bar.get_y() + bar.get_height()/2,
                f'{score:.2f}',
                ha='left', va='center', fontweight='bold'
            )
        
        ax.set_xlabel("Max Risk Score", fontsize=12)
        ax.set_ylabel("Asset", fontsize=12)
        ax.set_title(f"Top {top_n} Assets by Risk Score", fontsize=14, fontweight="bold")
        ax.set_xlim(0, 1.1)
        ax.grid(True, alpha=0.3, axis='x')
        
        plt.tight_layout()
        
        if save_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            save_path = self.output_dir / f"asset_risk_distribution_{timestamp}.png"
        else:
            save_path = Path(save_path)
        
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        self.logger.info(f"Asset risk distribution сохранена: {save_path}")
        
        return str(save_path)
    
    def create_security_report(
        self,
        passports: List[CVEPassport],
        risk_calculations: List[RiskCalculation],
        assets: List[Asset],
        output_path: Optional[str] = None
    ) -> Dict[str, str]:
        """
        Создание полного отчета безопасности
        
        Args:
            passports: Список паспортов CVE
            risk_calculations: Список расчетов рисков
            assets: Список активов
            output_path: Базовый путь для сохранения
            
        Returns:
            Словарь с путями к созданным графикам
        """
        if output_path:
            self.output_dir = Path(output_path)
            self.output_dir.mkdir(parents=True, exist_ok=True)
        
        report_files = {}
        
        # Heatmap рисков
        report_files["heatmap"] = self.plot_risk_heatmap(risk_calculations, assets)
        
        # Распределение по критичности
        report_files["severity"] = self.plot_severity_distribution(passports)
        
        # Временная линия
        report_files["timeline"] = self.plot_cvss_timeline(passports)
        
        # Распределение по активам
        report_files["asset_risks"] = self.plot_risk_distribution_by_asset(
            risk_calculations, assets
        )
        
        self.logger.info(f"Security report создан: {len(report_files)} графиков")
        
        return report_files
