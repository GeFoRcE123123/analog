"""
Универсальный парсер уязвимостей от различных вендоров
Поддерживает API, CSV, JSON и веб-скрейпинг
"""

import requests
import logging
import time
import json
import csv
import re
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import io

# Import the correct Vulnerability entity (the extended one)
from models.entities import Vulnerability

logger = logging.getLogger(__name__)


class UniversalVendorParser:
    """Универсальный парсер для всех источников"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Конфигурация источников
        self.sources = {
            # API источники
            'ubuntu': {
                'type': 'api',
                'url': 'https://ubuntu.com/security/cves.json',
                'parser': self._parse_ubuntu
            },
            'debian': {
                'type': 'api',
                'url': 'https://security-tracker.debian.org/tracker/data/json',
                'parser': self._parse_debian
            },
            
            # CSV источники
            'hp': {
                'type': 'csv',
                'url': 'https://support.hp.com/us-en/security-bulletins',
                'parser': self._parse_hp_csv
            },
            'splunk': {
                'type': 'csv',
                'url': 'https://advisory.splunk.com/advisories',
                'parser': self._parse_splunk_csv
            },
            
            # JSON источники
            'fedisec': {
                'type': 'json',
                'url': 'https://raw.githubusercontent.com/FediSecFeeds/FediSecFeeds.github.io/main/data/cves.json',
                'parser': self._parse_fedisec_json
            },
            
            # Web scraping источники
            'moxa': {
                'type': 'scrape',
                'url': 'https://www.moxa.com/en/support/support/security-advisory',
                'parser': self._parse_moxa_scrape
            },
            'adobe': {
                'type': 'scrape',
                'url': 'https://helpx.adobe.com/security.html',
                'parser': self._parse_adobe_scrape
            },
            'cisco': {
                'type': 'scrape',
                'url': 'https://sec.cloudapps.cisco.com/security/center/publicationListing.x',
                'parser': self._parse_cisco_scrape
            },
            'huntr': {
                'type': 'scrape',
                'url': 'https://huntr.com/bounties/hacktivity',
                'parser': self._parse_huntr_scrape
            }
        }
    
    def parse_all_sources(self, sources: Optional[List[str]] = None, limit_per_source: int = 100) -> Dict[str, Any]:
        """Парсинг из всех источников"""
        if sources is None:
            sources = list(self.sources.keys())
        
        results = {
            'total_parsed': 0,
            'total_saved': 0,
            'by_source': {},
            'errors': []
        }
        
        for source_name in sources:
            if source_name not in self.sources:
                logger.warning(f"Unknown source: {source_name}")
                continue
            
            logger.info(f"🔍 Parsing {source_name}...")
            
            try:
                source_config = self.sources[source_name]
                vulnerabilities = source_config['parser'](limit=limit_per_source)
                
                results['by_source'][source_name] = {
                    'parsed': len(vulnerabilities),
                    'data': vulnerabilities
                }
                results['total_parsed'] += len(vulnerabilities)
                
                logger.info(f"✅ {source_name}: {len(vulnerabilities)} vulnerabilities")
                
            except Exception as e:
                error_msg = f"{source_name}: {str(e)}"
                results['errors'].append(error_msg)
                logger.error(f"❌ {error_msg}")
        
        return results
    
    def save_parsed_vulnerabilities(self, parsed_results: Dict[str, Any]) -> int:
        """Сохранить спарсенные уязвимости в БД"""
        try:
            from models.database import DatabaseManager
            from models.entities import Vulnerability
            from datetime import datetime
            
            db_manager = DatabaseManager()
            saved_count = 0
            
            for source_name, source_data in parsed_results.get('by_source', {}).items():
                vulnerabilities = source_data.get('data', [])
                
                for vuln_data in vulnerabilities:
                    try:
                        # Проверяем, существует ли уже уязвимость с таким CVE ID
                        cve_id = vuln_data.get('cve_id')
                        if cve_id and self._check_cve_exists(db_manager, cve_id):
                            logger.info(f"⚠️ CVE already exists: {cve_id}")
                            continue
                        
                        # Создаем объект Vulnerability
                        vulnerability = self._create_vulnerability_from_parsed_data(vuln_data, source_name)
                        
                        # Сохраняем в БД
                        if self._save_vulnerability(db_manager, vulnerability):
                            saved_count += 1
                            logger.info(f"✅ Saved vulnerability: {vulnerability.title}")
                        else:
                            logger.error(f"❌ Failed to save vulnerability: {vulnerability.title}")
                            
                    except Exception as e:
                        logger.error(f"Error saving vulnerability from {source_name}: {e}")
            
            return saved_count
            
        except Exception as e:
            logger.error(f"Error saving parsed vulnerabilities: {e}")
            return 0
    
    def _check_cve_exists(self, db_manager, cve_id: str) -> bool:
        """Проверить существует ли CVE в БД"""
        try:
            query = "SELECT 1 FROM vulnerabilities WHERE cve_id = %s LIMIT 1"
            with db_manager.connection.cursor() as cursor:
                cursor.execute(query, (cve_id,))
                return cursor.fetchone() is not None
        except Exception as e:
            logger.error(f"Error checking if CVE {cve_id} exists: {e}")
            return False
    
    def _create_vulnerability_from_parsed_data(self, vuln_data: Dict, source_name: str) -> Vulnerability:
        """Создать объект Vulnerability из спарсенных данных с адаптивными метриками"""
        # Получаем основное описание
        description = vuln_data.get('description', '') or vuln_data.get('title', '')
        if not description:
            description = f"Vulnerability from {source_name}: {vuln_data.get('cve_id', vuln_data.get('title', 'Unknown'))}"
        
        # Определяем severity и CVSS score
        severity = vuln_data.get('severity', 'medium').lower()
        cvss_score = float(vuln_data.get('cvss_score', 0.0) or 0.0)
        
        # If no CVSS score, try to derive from severity
        if cvss_score == 0.0:
            severity_cvss_map = {
                'critical': 9.0,
                'high': 7.5,
                'medium': 5.0,
                'low': 2.0,
                'unknown': 5.0
            }
            cvss_score = severity_cvss_map.get(severity, 5.0)
        
        # Normalize severity based on CVSS score if we have it
        if cvss_score > 0:
            if cvss_score >= 9.0:
                severity = 'critical'
            elif cvss_score >= 7.0:
                severity = 'high'
            elif cvss_score >= 4.0:
                severity = 'medium'
            else:
                severity = 'low'
        
        # Определяем risk level с более адаптивным подходом
        risk_level = self._calculate_adaptive_risk_level(cvss_score, severity, vuln_data)
        
        # Создаем базовый объект Vulnerability
        vulnerability = Vulnerability(
            id=0,  # БД сама назначит ID
            title=vuln_data.get('cve_id', vuln_data.get('title', f'Unknown from {source_name}'))[:200],
            description=description[:1000],  # Ограничиваем длину
            severity=severity,
            status='new',
            assigned_operator=None,
            created_date=datetime.now(),
            completed_date=None,
            approved=False,
            modifications=0,
            cvss_score=cvss_score,
            risk_level=risk_level,
            category='security'
        )
        
        # Добавляем дополнительные поля как атрибуты через setattr
        # Это обходит проблему с конструктором
        setattr(vulnerability, 'cve_id', vuln_data.get('cve_id'))
        setattr(vulnerability, 'source_identifier', source_name)
        setattr(vulnerability, 'published', self._parse_date(vuln_data.get('published')))
        setattr(vulnerability, 'last_modified', self._parse_date(vuln_data.get('updated') or vuln_data.get('published')))  # Use updated or published
        setattr(vulnerability, 'vuln_status', 'Analyzed')  # Default status
        setattr(vulnerability, 'url', vuln_data.get('url'))
        setattr(vulnerability, 'affected_packages', vuln_data.get('affected_packages', []))
        
        # Create proper descriptions format
        descriptions = []
        if description:
            descriptions.append({'lang': 'en', 'value': description[:1000]})
        setattr(vulnerability, 'descriptions', descriptions)
        
        # Create metrics with CVSS data and adaptive scoring
        metrics = self._create_adaptive_metrics(cvss_score, severity, vuln_data)
        setattr(vulnerability, 'metrics', metrics)
        
        # Create weaknesses if CWE data is available
        weaknesses = []
        if vuln_data.get('cwe'):
            weaknesses.append({
                'source': source_name,
                'type': 'Primary',
                'description': vuln_data['cwe']
            })
        setattr(vulnerability, 'weaknesses', weaknesses)
        
        # Create configurations if package data is available
        configurations = self._create_adaptive_configurations(vuln_data)
        setattr(vulnerability, 'configurations', configurations)
        
        # Create references
        references = self._create_adaptive_references(vuln_data, source_name)
        setattr(vulnerability, 'references', references)
        
        # Initialize other fields with adaptive values
        setattr(vulnerability, 'vendor_comments', [])
        setattr(vulnerability, 'is_ai_related', self._detect_ai_related_vulnerability(vuln_data))
        setattr(vulnerability, 'ai_confidence', self._calculate_ai_confidence_score(vuln_data))
        setattr(vulnerability, 'has_kev', self._check_kev_status(vuln_data))
        setattr(vulnerability, 'has_cert_alerts', self._check_cert_alerts(vuln_data))
        
        return vulnerability
    
    def _calculate_adaptive_risk_level(self, cvss_score: float, severity: str, vuln_data: Dict) -> str:
        """Рассчитать адаптивный уровень риска на основе CVSS, severity и дополнительных данных"""
        # Start with CVSS-based risk level
        if cvss_score >= 9.0:
            risk_level = 'critical'
        elif cvss_score >= 7.0:
            risk_level = 'high'
        elif cvss_score >= 4.0:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        # Adjust based on additional factors
        affected_packages = vuln_data.get('affected_packages', [])
        if affected_packages:
            # If critical system packages are affected, increase risk
            critical_packages = ['kernel', 'libc', 'openssl', 'systemd', 'sudo', 'bash']
            for pkg in affected_packages:
                if any(critical_pkg in pkg.lower() for critical_pkg in critical_packages):
                    if risk_level == 'medium':
                        risk_level = 'high'
                    elif risk_level == 'low':
                        risk_level = 'medium'
                    break
        
        # Check for KEV (Known Exploited Vulnerabilities)
        if self._check_kev_status(vuln_data):
            # KEV vulnerabilities should be at least high risk
            if risk_level in ['low', 'medium']:
                risk_level = 'high'
        
        return risk_level
    
    def _create_adaptive_metrics(self, cvss_score: float, severity: str, vuln_data: Dict) -> Dict:
        """Создать адаптивные метрики на основе доступных данных"""
        metrics = {}
        
        # Add CVSS metrics if we have a score
        if cvss_score > 0:
            metrics['cvss_v3'] = {
                'version': '3.1',
                'baseScore': cvss_score,
                'baseSeverity': severity.capitalize()
            }
        
        # Add temporal metrics if we have additional data
        temporal_score = self._calculate_temporal_score(cvss_score, vuln_data)
        if temporal_score != cvss_score and temporal_score > 0:
            metrics['cvss_v3_temporal'] = {
                'version': '3.1',
                'baseScore': cvss_score,
                'temporalScore': temporal_score,
                'baseSeverity': severity.capitalize()
            }
        
        # Add environmental metrics for critical assets
        environmental_score = self._calculate_environmental_score(cvss_score, vuln_data)
        if environmental_score != cvss_score and environmental_score > 0:
            metrics['cvss_v3_environmental'] = {
                'version': '3.1',
                'baseScore': cvss_score,
                'environmentalScore': environmental_score,
                'baseSeverity': severity.capitalize()
            }
        
        return metrics
    
    def _calculate_temporal_score(self, base_score: float, vuln_data: Dict) -> float:
        """Рассчитать временную оценку на основе статуса исправления"""
        # Start with base score
        temporal_score = base_score
        
        # Adjust based on exploit availability
        if self._check_kev_status(vuln_data):
            # KEV vulnerabilities get a boost
            temporal_score = min(10.0, temporal_score + 1.0)
        elif vuln_data.get('has_exploit', False):
            # Known exploits get a smaller boost
            temporal_score = min(10.0, temporal_score + 0.5)
        
        # Adjust based on patch availability
        affected_packages = vuln_data.get('affected_packages', [])
        if affected_packages:
            # If no patches available, increase score
            # This is a simplified check - in reality we'd check each package
            temporal_score = min(10.0, temporal_score + 0.2)
        
        return round(temporal_score, 1)
    
    def _calculate_environmental_score(self, base_score: float, vuln_data: Dict) -> float:
        """Рассчитать экологическую оценку на основе критичности активов"""
        environmental_score = base_score
        
        # Check for critical system packages
        affected_packages = vuln_data.get('affected_packages', [])
        critical_packages = ['kernel', 'libc', 'openssl', 'systemd', 'sudo', 'bash', 'ssh', 'apache', 'nginx']
        
        for pkg in affected_packages:
            if any(critical_pkg in pkg.lower() for critical_pkg in critical_packages):
                # Increase score for critical system components
                environmental_score = min(10.0, environmental_score + 1.5)
                break
        
        return round(environmental_score, 1)
    
    def _create_adaptive_configurations(self, vuln_data: Dict) -> List:
        """Создать адаптивные конфигурации на основе данных о пакетах"""
        configurations = []
        affected_packages = vuln_data.get('affected_packages', [])
        
        if affected_packages:
            nodes = []
            for pkg in affected_packages[:10]:  # Limit to 10 packages
                if isinstance(pkg, str):
                    # Create CPE match for the package
                    nodes.append({
                        'operator': 'OR',
                        'cpe_match': [{
                            'vulnerable': True,
                            'cpe23Uri': f"cpe:2.3:a:*:{pkg}:*:*:*:*:*:*:*:*"
                        }]
                    })
            if nodes:
                configurations.append({
                    'nodes': nodes,
                    'operator': 'OR'
                })
        
        return configurations
    
    def _create_adaptive_references(self, vuln_data: Dict, source_name: str) -> List:
        """Создать адаптивные ссылки на основе доступных данных"""
        references = []
        
        # Add primary URL
        if vuln_data.get('url'):
            references.append({
                'url': vuln_data['url'],
                'source': source_name
            })
        
        # Add CVE reference if available
        if vuln_data.get('cve_id'):
            references.append({
                'url': f"https://nvd.nist.gov/vuln/detail/{vuln_data['cve_id']}",
                'source': 'NVD'
            })
        
        # Add additional references from data
        additional_refs = vuln_data.get('references', [])
        if isinstance(additional_refs, list):
            references.extend(additional_refs)
        
        return references
    
    def _detect_ai_related_vulnerability(self, vuln_data: Dict) -> bool:
        """Определить, связана ли уязвимость с ИИ"""
        ai_keywords = ['ai', 'machine learning', 'neural', 'tensorflow', 'pytorch', 'model', 'algorithm', 'ml', 'deep learning']
        description = (vuln_data.get('description', '') or '').lower()
        title = (vuln_data.get('title', '') or '').lower()
        
        return any(keyword in description or keyword in title for keyword in ai_keywords)
    
    def _calculate_ai_confidence_score(self, vuln_data: Dict) -> float:
        """Рассчитать уровень уверенности для ИИ-уязвимостей"""
        if self._detect_ai_related_vulnerability(vuln_data):
            # Base confidence for AI-related vulnerabilities
            return 0.8
        return 0.0
    
    def _check_kev_status(self, vuln_data: Dict) -> bool:
        """Проверить статус KEV (Known Exploited Vulnerabilities)"""
        # In a real implementation, we would check against the CISA KEV catalog
        # For now, we'll use a simple heuristic
        description = (vuln_data.get('description', '') or '').lower()
        title = (vuln_data.get('title', '') or '').lower()
        
        kev_indicators = ['exploited', 'in the wild', 'active exploitation', 'known exploited']
        return any(indicator in description or indicator in title for indicator in kev_indicators)
    
    def _check_cert_alerts(self, vuln_data: Dict) -> bool:
        """Проверить наличие оповещений CERT"""
        # In a real implementation, we would check against CERT alerts
        # For now, we'll return False
        return False
    
    def _parse_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """Парсинг даты из строки"""
        if not date_str:
            return None
        
        try:
            # Пробуем разные форматы дат
            if 'T' in date_str:
                # ISO формат
                date_str = date_str.replace('Z', '+00:00')
                return datetime.fromisoformat(date_str)
            else:
                # Простой формат YYYY-MM-DD
                return datetime.strptime(date_str, '%Y-%m-%d')
        except (ValueError, TypeError):
            return None
    
    def _save_vulnerability(self, db_manager, vulnerability: Vulnerability) -> bool:
        """Сохранить уязвимость в БД"""
        try:
            from models.postgres_repositories import PostgresVulnerabilityRepository
            
            repo = PostgresVulnerabilityRepository(db_manager.connection)
            return repo.add(vulnerability)
        except Exception as e:
            logger.error(f"Error saving vulnerability: {e}")
            return False
    
    # === API ПАРСЕРЫ ===
    
    def _parse_ubuntu(self, limit: int = 100) -> List[Dict]:
        """Парсинг Ubuntu Security API с поддержкой пагинации"""
        vulnerabilities = []
        offset = 0
        batch_size = 20  # Process in batches
        remaining = limit
        
        try:
            while remaining > 0 and len(vulnerabilities) < limit:
                current_batch_size = min(batch_size, remaining)
                
                # Ubuntu API возвращает JSON с CVE
                response = self.session.get(
                    'https://ubuntu.com/security/cves.json',
                    params={'limit': current_batch_size, 'offset': offset},
                    timeout=30
                )
                response.raise_for_status()
                
                data = response.json()
                cves = data.get('cves', [])
                
                # If no more CVEs, break
                if not cves:
                    break
                
                for cve_data in cves:
                    if len(vulnerabilities) >= limit:
                        break
                    
                    cve_id = cve_data.get('id')
                    if not cve_id:
                        continue
                    
                    # Get detailed CVE information
                    detailed_info = self._get_ubuntu_cve_details(cve_id)
                    
                    # Use detailed info if available, otherwise fallback to basic data
                    if detailed_info:
                        vulnerabilities.append(detailed_info)
                    else:
                        # Fallback to basic parsing
                        description = cve_data.get('description', '')
                        if not description:
                            description = f"Security advisory for {cve_id} in Ubuntu"
                        
                        # Handle CVSS data properly
                        cvss_score = 0.0
                        cvss_data = cve_data.get('cvss')
                        if cvss_data:
                            if isinstance(cvss_data, dict):
                                cvss_score = float(cvss_data.get('base_score', 0) or cvss_data.get('score', 0) or 0)
                            elif isinstance(cvss_data, (int, float)):
                                cvss_score = float(cvss_data)
                        
                        # Determine severity from priority or CVSS
                        severity = cve_data.get('priority', 'unknown').lower()
                        if severity == 'unknown' and cvss_score > 0:
                            # Derive severity from CVSS score
                            if cvss_score >= 9.0:
                                severity = 'critical'
                            elif cvss_score >= 7.0:
                                severity = 'high'
                            elif cvss_score >= 4.0:
                                severity = 'medium'
                            else:
                                severity = 'low'
                        
                        vuln = {
                            'source': 'ubuntu',
                            'cve_id': cve_id,
                            'title': description[:200],
                            'description': description,
                            'severity': severity,
                            'published': cve_data.get('published'),
                            'url': f"https://ubuntu.com/security/{cve_id}",
                            'cvss_score': cvss_score,
                            'affected_packages': [p.get('name') for p in cve_data.get('packages', [])]
                        }
                        vulnerabilities.append(vuln)
                
                # Update for next batch
                offset += len(cves)
                remaining -= len(cves)
                
                # If we got fewer CVEs than requested, we've reached the end
                if len(cves) < current_batch_size:
                    break
                
        except Exception as e:
            logger.error(f"Ubuntu API error: {e}")
        
        return vulnerabilities
    
    def _get_ubuntu_cve_details(self, cve_id: str) -> Optional[Dict]:
        """Получить детальную информацию о CVE от Ubuntu"""
        try:
            response = self.session.get(
                f'https://ubuntu.com/security/{cve_id}',
                timeout=30
            )
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Extract description - look for the main content area
            description = ''
            
            # Try to find the main description in common locations
            # Look for meta description first
            meta_desc = soup.find('meta', attrs={'name': 'description'})
            if meta_desc:
                description = str(meta_desc.get('content', ''))
            
            # If no meta description, look for specific content divs
            if not description:
                # Look for the main article or content div
                content_div = soup.find('article') or soup.find('main') or soup.find('div', class_=re.compile(r'content|main|body', re.I))
                if content_div:
                    # Get text but exclude navigation and footer elements
                    for nav_elem in content_div.find_all(['nav', 'footer', 'header', 'aside']):
                        nav_elem.decompose()
                    description = str(content_div.get_text(strip=True))
            
            # If still no description, get text from paragraphs
            if not description:
                paragraphs = soup.find_all('p')
                # Join paragraphs that seem to contain meaningful content
                desc_parts = []
                for p in paragraphs:
                    text = str(p.get_text(strip=True))
                    if text and len(text) > 50 and 'copyright' not in text.lower() and 'ubuntu' not in text.lower():
                        desc_parts.append(text)
                if desc_parts:
                    description = ' '.join(desc_parts)
            
            # Clean up the description
            if description:
                # Remove excessive whitespace
                description = str(re.sub(r'\s+', ' ', description)).strip()
            
            # Extract severity from priority information
            severity = 'unknown'
            
            # Look for priority explicitly mentioned
            priority_text = str(soup.get_text())
            priority_match = re.search(r'(Priority|Severity):\s*(\w+)', priority_text, re.I)
            if priority_match:
                severity_text = priority_match.group(2).lower()
                if 'critical' in severity_text:
                    severity = 'critical'
                elif 'high' in severity_text:
                    severity = 'high'
                elif 'medium' in severity_text or 'moderate' in severity_text:
                    severity = 'medium'
                elif 'low' in severity_text:
                    severity = 'low'
            
            # Extract published date
            published = None
            # Look for date patterns
            date_text = str(soup.get_text())
            date_matches = re.findall(r'\b\d{4}-\d{2}-\d{2}\b', date_text)
            if date_matches:
                published = date_matches[0]
            
            # Extract affected packages
            packages = []
            # Look for package links in a more targeted way
            package_links = soup.find_all('a', href=re.compile(r'/security/cve\?package='))
            for link in package_links:
                package_name = str(link.get_text(strip=True))
                if package_name and len(package_name) > 1 and package_name.lower() not in ['package', 'packages']:
                    packages.append(package_name)
            
            # If we don't have meaningful data, return None to use fallback
            if not description or len(description) < 50:
                # But if we have packages, we might still want to use this data
                if not packages:
                    return None
            
            # Create a cleaner title
            title = description[:200] if description else f"{cve_id} - Ubuntu Security Advisory"
            if len(title) > 150:
                # Try to find a sentence boundary for cleaner title
                title_str = str(title[:150])
                sentence_end = title_str.rfind('. ')
                if sentence_end > 50:
                    title = title_str[:sentence_end + 1]
                else:
                    title = title_str + "..."
            
            # Create vulnerability data
            vuln = {
                'source': 'ubuntu',
                'cve_id': cve_id,
                'title': str(title),
                'description': str(description) if description else f"Detailed information for {cve_id}",
                'severity': severity,
                'published': published,
                'url': f"https://ubuntu.com/security/{cve_id}",
                'cvss_score': 0.0,
                'affected_packages': list(set(packages))[:10]  # Remove duplicates and limit to 10
            }
            
            return vuln
            
        except Exception as e:
            logger.debug(f"Could not get detailed Ubuntu CVE info for {cve_id}: {e}")
            return None
    
    def _parse_debian(self, limit: int = 100) -> List[Dict]:
        """Парсинг Debian Security Tracker с поддержкой пагинации"""
        vulnerabilities = []
        
        try:
            # Debian возвращает огромный JSON со всеми CVE
            response = self.session.get(
                'https://security-tracker.debian.org/tracker/data/json',
                timeout=60
            )
            response.raise_for_status()
            
            all_cves = response.json()
            
            # Sort CVEs by key (which should be roughly chronological for CVE numbers)
            sorted_cve_items = sorted(all_cves.items(), key=lambda x: x[0], reverse=True)
            
            # Берем последние CVE в пределах лимита
            cve_items = sorted_cve_items[:limit]
            
            for cve_id, cve_data in cve_items:
                # Try to get detailed information by scraping the CVE page
                detailed_info = self._get_debian_cve_details(cve_id)
                
                if detailed_info:
                    vulnerabilities.append(detailed_info)
                else:
                    # Fallback to basic parsing
                    # Create a better description if the original is empty
                    description = cve_data.get('description', '')
                    if not description:
                        # Try to get description from releases or other fields
                        releases_info = cve_data.get('releases', {})
                        if releases_info:
                            # Get the first release description
                            for release_name, release_data in list(releases_info.items())[:3]:
                                if release_data.get('description'):
                                    description = f"{cve_id} affects {release_name}: {release_data.get('description', '')}"
                                    break
                    
                    # If still no description, create a generic one
                    if not description:
                        description = f"Security advisory for {cve_id} in Debian Linux"
                    
                    # Try to determine severity from releases
                    severity = cve_data.get('scope', 'unknown').lower()
                    if severity == 'unknown' or not severity:
                        # Check releases for severity info
                        releases_info = cve_data.get('releases', {})
                        for release_data in releases_info.values():
                            release_severity = release_data.get('urgency', '').lower()
                            if 'high' in release_severity or 'critical' in release_severity:
                                severity = 'high'
                                break
                            elif 'medium' in release_severity:
                                severity = 'medium'
                                break
                            elif 'low' in release_severity:
                                severity = 'low'
                    
                    vuln = {
                        'source': 'debian',
                        'cve_id': cve_id,
                        'title': description[:200],
                        'description': description,
                        'severity': severity,
                        'url': f"https://security-tracker.debian.org/tracker/{cve_id}",
                        'releases': list(cve_data.get('releases', {}).keys())
                    }
                    vulnerabilities.append(vuln)
                
        except Exception as e:
            logger.error(f"Debian API error: {e}")
        
        return vulnerabilities
    
    def _get_debian_cve_details(self, cve_id: str) -> Optional[Dict]:
        """Получить детальную информацию о CVE от Debian"""
        try:
            response = self.session.get(
                f'https://security-tracker.debian.org/tracker/{cve_id}',
                timeout=30
            )
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Extract description
            description_elem = soup.find('td', text='Description')
            description = ''
            if description_elem:
                # Get the next sibling which should contain the description
                desc_td = description_elem.find_next('td')
                if desc_td:
                    description = desc_td.get_text(strip=True)
            
            # If no description found, try alternative method
            if not description:
                desc_elem = soup.find('b', text='Description')
                if desc_elem:
                    parent = desc_elem.parent
                    if parent:
                        # Get text from the parent or its siblings
                        description = parent.get_text(separator=' ', strip=True)
            
            # Extract severity from the page content
            severity = 'unknown'
            page_text = soup.get_text().lower()
            if 'critical' in page_text:
                severity = 'critical'
            elif 'high' in page_text:
                severity = 'high'
            elif 'medium' in page_text or 'moderate' in page_text:
                severity = 'medium'
            elif 'low' in page_text:
                severity = 'low'
            
            # Extract affected packages
            packages = []
            # Look for package names in the table
            package_links = soup.find_all('a', href=re.compile(r'/tracker/source-package/'))
            for link in package_links:
                package_name = link.get_text(strip=True)
                if package_name and package_name not in packages:
                    packages.append(package_name)
            
            # If we don't have good data, return None to use fallback
            if not description and not packages:
                return None
            
            # Create vulnerability data
            vuln = {
                'source': 'debian',
                'cve_id': cve_id,
                'title': description[:200] if description else f"{cve_id} - Debian Security Advisory",
                'description': description if description else f"Detailed information for {cve_id}",
                'severity': severity,
                'url': f"https://security-tracker.debian.org/tracker/{cve_id}",
                'affected_packages': packages[:10]  # Limit to 10 packages
            }
            
            return vuln
            
        except Exception as e:
            logger.debug(f"Could not get detailed Debian CVE info for {cve_id}: {e}")
            return None
    
    # === CSV ПАРСЕРЫ ===
    
    def _parse_hp_csv(self, limit: int = 100) -> List[Dict]:
        """Парсинг HP Security Bulletins (CSV)"""
        vulnerabilities = []
        
        try:
            response = self.session.get(
                'https://support.hp.com/us-en/security-bulletins',
                timeout=30
            )
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Ищем ссылку на CSV или парсим таблицу
            csv_link = soup.find('a', href=re.compile(r'\.csv'))
            
            if csv_link:
                # Получаем URL как строку
                csv_url = str(csv_link.get('href', ''))
                if csv_url and not csv_url.startswith('http'):
                    csv_url = 'https://support.hp.com' + csv_url
                
                if csv_url:
                    csv_response = self.session.get(csv_url, timeout=30)
                    csv_data = csv.DictReader(io.StringIO(csv_response.text))
                    
                    for row in list(csv_data)[:limit]:
                        vuln = {
                            'source': 'hp',
                            'cve_id': row.get('CVE', ''),
                            'title': row.get('Title', '')[:200],
                            'description': row.get('Description', ''),
                            'severity': row.get('Severity', 'unknown'),
                            'published': row.get('Published', ''),
                            'url': row.get('URL', '')
                        }
                        vulnerabilities.append(vuln)
            else:
                # Парсим таблицу на странице
                table = soup.find('table', class_=re.compile(r'security|bulletin'))
                if table:
                    rows = table.find_all('tr')[1:limit+1]  # Пропускаем заголовок
                    
                    for row in rows:
                        cells = row.find_all('td')
                        if len(cells) >= 3:
                            # Получаем URL безопасно
                            url = ''
                            first_cell = cells[0]
                            if first_cell:
                                link = first_cell.find('a')
                                if link:
                                    url = link.get('href', '')
                            
                            vuln = {
                                'source': 'hp',
                                'title': cells[0].get_text(strip=True)[:200] if cells[0] else '',
                                'cve_id': self._extract_cve_from_text(cells[1].get_text() if len(cells) > 1 else ''),
                                'severity': cells[2].get_text(strip=True) if len(cells) > 2 else 'unknown',
                                'url': url
                            }
                            vulnerabilities.append(vuln)
                
        except Exception as e:
            logger.error(f"HP CSV error: {e}")
        
        return vulnerabilities
    
    def _parse_splunk_csv(self, limit: int = 100) -> List[Dict]:
        """Парсинг Splunk Advisories (CSV)"""
        vulnerabilities = []
        
        try:
            response = self.session.get(
                'https://advisory.splunk.com/advisories',
                timeout=30
            )
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Ищем export кнопку или парсим таблицу
            advisories = soup.find_all('div', class_=re.compile(r'advisory|card'))[:limit]
            
            for advisory in advisories:
                title_elem = advisory.find(['h3', 'h4', 'a'])
                cve_text = advisory.get_text()
                
                vuln = {
                    'source': 'splunk',
                    'title': title_elem.get_text(strip=True)[:200] if title_elem else '',
                    'cve_id': self._extract_cve_from_text(cve_text),
                    'description': advisory.get_text(strip=True)[:500],
                    'url': title_elem['href'] if title_elem and title_elem.name == 'a' else ''
                }
                vulnerabilities.append(vuln)
                
        except Exception as e:
            logger.error(f"Splunk CSV error: {e}")
        
        return vulnerabilities
    
    # === JSON ПАРСЕРЫ ===
    
    def _parse_fedisec_json(self, limit: int = 100) -> List[Dict]:
        """Парсинг FediSecFeeds JSON"""
        vulnerabilities = []
        
        try:
            response = self.session.get(
                'https://raw.githubusercontent.com/FediSecFeeds/FediSecFeeds.github.io/main/data/cves.json',
                timeout=30
            )
            response.raise_for_status()
            
            data = response.json()
            
            for cve_data in data[:limit]:
                vuln = {
                    'source': 'fedisec',
                    'cve_id': cve_data.get('cve_id'),
                    'title': cve_data.get('title', '')[:200],
                    'description': cve_data.get('description', ''),
                    'severity': cve_data.get('severity', 'unknown'),
                    'published': cve_data.get('published'),
                    'cvss_score': cve_data.get('cvss_score'),
                    'url': cve_data.get('url', '')
                }
                vulnerabilities.append(vuln)
                
        except Exception as e:
            logger.error(f"FediSec JSON error: {e}")
        
        return vulnerabilities
    
    # === WEB SCRAPING ПАРСЕРЫ ===
    
    def _parse_moxa_scrape(self, limit: int = 100) -> List[Dict]:
        """Парсинг Moxa Security Advisory"""
        vulnerabilities = []
        
        try:
            driver = self._get_selenium_driver()
            driver.get('https://www.moxa.com/en/support/support/security-advisory')
            
            WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "table, .advisory"))
            )
            
            soup = BeautifulSoup(driver.page_source, 'html.parser')
            driver.quit()
            
            # Парсим таблицу или карточки advisory
            advisories = soup.find_all(['tr', 'div'], class_=re.compile(r'advisory|row'))[:limit]
            
            for advisory in advisories:
                text = advisory.get_text()
                link = advisory.find('a')
                
                vuln = {
                    'source': 'moxa',
                    'title': link.get_text(strip=True)[:200] if link else text[:200],
                    'cve_id': self._extract_cve_from_text(text),
                    'description': text[:500],
                    'url': link['href'] if link else ''
                }
                
                if vuln['cve_id']:
                    vulnerabilities.append(vuln)
                    
        except Exception as e:
            logger.error(f"Moxa scrape error: {e}")
        
        return vulnerabilities
    
    def _parse_adobe_scrape(self, limit: int = 100) -> List[Dict]:
        """Парсинг Adobe Security"""
        vulnerabilities = []
        
        try:
            response = self.session.get(
                'https://helpx.adobe.com/security.html',
                timeout=30
            )
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Adobe использует специфичную структуру
            bulletins = soup.find_all(['article', 'div'], class_=re.compile(r'bulletin|security'))[:limit]
            
            for bulletin in bulletins:
                title_elem = bulletin.find(['h2', 'h3', 'a'])
                
                vuln = {
                    'source': 'adobe',
                    'title': title_elem.get_text(strip=True)[:200] if title_elem else '',
                    'cve_id': self._extract_cve_from_text(bulletin.get_text()),
                    'description': bulletin.get_text(strip=True)[:500],
                    'url': title_elem['href'] if title_elem and title_elem.name == 'a' else ''
                }
                
                if vuln['cve_id']:
                    vulnerabilities.append(vuln)
                    
        except Exception as e:
            logger.error(f"Adobe scrape error: {e}")
        
        return vulnerabilities
    
    def _parse_cisco_scrape(self, limit: int = 100) -> List[Dict]:
        """Парсинг Cisco Security Center"""
        vulnerabilities = []
        
        try:
            driver = self._get_selenium_driver()
            driver.get('https://sec.cloudapps.cisco.com/security/center/publicationListing.x')
            
            WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "table, .publication"))
            )
            
            soup = BeautifulSoup(driver.page_source, 'html.parser')
            driver.quit()
            
            publications = soup.find_all(['tr', 'div'], class_=re.compile(r'publication|advisory'))[:limit]
            
            for pub in publications:
                text = pub.get_text()
                link = pub.find('a')
                
                vuln = {
                    'source': 'cisco',
                    'title': link.get_text(strip=True)[:200] if link else text[:200],
                    'cve_id': self._extract_cve_from_text(text),
                    'description': text[:500],
                    'url': link['href'] if link else ''
                }
                
                if vuln['cve_id']:
                    vulnerabilities.append(vuln)
                    
        except Exception as e:
            logger.error(f"Cisco scrape error: {e}")
        
        return vulnerabilities
    
    def _parse_huntr_scrape(self, limit: int = 100) -> List[Dict]:
        """Парсинг Huntr Bounties"""
        vulnerabilities = []
        
        try:
            driver = self._get_selenium_driver()
            driver.get('https://huntr.com/bounties/hacktivity')
            
            time.sleep(3)  # Ждем загрузки JS
            
            soup = BeautifulSoup(driver.page_source, 'html.parser')
            driver.quit()
            
            bounties = soup.find_all(['div', 'article'], class_=re.compile(r'bounty|activity'))[:limit]
            
            for bounty in bounties:
                title_elem = bounty.find(['h3', 'h4', 'a'])
                
                vuln = {
                    'source': 'huntr',
                    'title': title_elem.get_text(strip=True)[:200] if title_elem else '',
                    'cve_id': self._extract_cve_from_text(bounty.get_text()),
                    'description': bounty.get_text(strip=True)[:500],
                    'url': title_elem['href'] if title_elem and title_elem.name == 'a' else ''
                }
                
                if vuln['cve_id'] or vuln['title']:
                    vulnerabilities.append(vuln)
                    
        except Exception as e:
            logger.error(f"Huntr scrape error: {e}")
        
        return vulnerabilities
    
    # === УТИЛИТЫ ===
    
    def _get_selenium_driver(self):
        """Создание Selenium драйвера"""
        options = Options()
        options.add_argument("--headless")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-blink-features=AutomationControlled")
        
        driver = webdriver.Chrome(options=options)
        return driver
    
    def _extract_cve_from_text(self, text: str) -> str:
        """Извлечение CVE ID из текста"""
        match = re.search(r'CVE-\d{4}-\d{4,}', text, re.IGNORECASE)
        return match.group(0).upper() if match else ''
    
    def _extract_cvss(self, cvss_data: Dict) -> float:
        """Извлечение CVSS score"""
        if isinstance(cvss_data, dict):
            return float(cvss_data.get('base_score', 0) or cvss_data.get('score', 0) or 0)
        elif isinstance(cvss_data, (int, float)):
            return float(cvss_data)
        return 0.0


# Глобальный экземпляр
universal_vendor_parser = UniversalVendorParser()
