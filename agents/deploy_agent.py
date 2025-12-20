#!/usr/bin/env python3
"""
Агент автоматического деплоя на VM
Мониторит состояние деплоя и автоматически исправляет проблемы
"""
import subprocess
import json
import sys
import time
from typing import Dict, List, Optional
from pathlib import Path

class DeployAgent:
    """Автономный агент деплоя"""
    
    def __init__(self):
        self.vms = {
            'frontend': {'ip': '10.0.88.10', 'port': 80, 'service': 'nginx'},
            'backend': {'ip': '10.0.88.20', 'port': 5000, 'service': 'flask'},
            'database': {'ip': '10.0.88.11', 'port': 5432, 'service': 'postgres'},
            'parsers': {'ip': '10.0.88.23', 'port': None, 'service': 'python'}
        }
        self.deploy_status = {}
    
    def check_vm_availability(self, ip: str) -> bool:
        """Проверка доступности VM"""
        try:
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '2', ip],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def check_service_health(self, ip: str, port: Optional[int], service: str) -> Dict:
        """Проверка здоровья сервиса"""
        if not self.check_vm_availability(ip):
            return {'status': 'unreachable', 'message': 'VM недоступна'}
        
        if port:
            # Проверка порта
            try:
                import socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    return {'status': 'healthy', 'message': f'Порт {port} открыт'}
                else:
                    return {'status': 'unhealthy', 'message': f'Порт {port} закрыт'}
            except Exception as e:
                return {'status': 'error', 'message': str(e)}
        else:
            # Для сервисов без порта проверяем через SSH
            return {'status': 'unknown', 'message': 'Требуется проверка через SSH'}
    
    def deploy_service(self, service_name: str) -> Dict:
        """Деплой конкретного сервиса"""
        vm_config = self.vms.get(service_name)
        if not vm_config:
            return {'status': 'error', 'message': f'Неизвестный сервис: {service_name}'}
        
        ip = vm_config['ip']
        print(f"🚀 Деплой {service_name} на {ip}...", file=sys.stderr)
        
        # Проверка доступности
        if not self.check_vm_availability(ip):
            return {
                'status': 'failed',
                'message': f'VM {ip} недоступна',
                'service': service_name
            }
        
        # Запуск deploy.sh для конкретного сервиса
        try:
            result = subprocess.run(
                ['./deploy.sh', service_name],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                # Проверка здоровья после деплоя
                health = self.check_service_health(ip, vm_config['port'], vm_config['service'])
                return {
                    'status': 'success' if health['status'] == 'healthy' else 'partial',
                    'message': health['message'],
                    'service': service_name,
                    'health': health
                }
            else:
                return {
                    'status': 'failed',
                    'message': result.stderr,
                    'service': service_name,
                    'stdout': result.stdout
                }
        except subprocess.TimeoutExpired:
            return {
                'status': 'timeout',
                'message': 'Деплой превысил время ожидания',
                'service': service_name
            }
        except Exception as e:
            return {
                'status': 'error',
                'message': str(e),
                'service': service_name
            }
    
    def deploy_all(self) -> Dict:
        """Деплой всех сервисов"""
        results = {}
        
        # Порядок деплоя важен
        deploy_order = ['database', 'backend', 'frontend', 'parsers']
        
        for service in deploy_order:
            results[service] = self.deploy_service(service)
            time.sleep(2)  # Небольшая задержка между сервисами
        
        # Сводка
        successful = sum(1 for r in results.values() if r['status'] == 'success')
        total = len(results)
        
        return {
            'summary': {
                'total': total,
                'successful': successful,
                'failed': total - successful
            },
            'details': results
        }
    
    def monitor_deployment(self, interval: int = 30) -> None:
        """Мониторинг состояния деплоя"""
        print("🔍 Начало мониторинга деплоя...", file=sys.stderr)
        
        while True:
            status_report = {}
            for service_name, vm_config in self.vms.items():
                health = self.check_service_health(
                    vm_config['ip'],
                    vm_config['port'],
                    vm_config['service']
                )
                status_report[service_name] = {
                    'ip': vm_config['ip'],
                    'health': health
                }
            
            print(json.dumps(status_report, indent=2, ensure_ascii=False))
            time.sleep(interval)

def main():
    """Главная функция агента"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Агент автономного деплоя')
    parser.add_argument('--service', help='Деплой конкретного сервиса')
    parser.add_argument('--all', action='store_true', help='Деплой всех сервисов')
    parser.add_argument('--monitor', action='store_true', help='Мониторинг состояния')
    parser.add_argument('--interval', type=int, default=30, help='Интервал мониторинга (секунды)')
    
    args = parser.parse_args()
    
    agent = DeployAgent()
    
    if args.monitor:
        agent.monitor_deployment(args.interval)
    elif args.all:
        result = agent.deploy_all()
        print(json.dumps(result, indent=2, ensure_ascii=False))
    elif args.service:
        result = agent.deploy_service(args.service)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        parser.print_help()

if __name__ == '__main__':
    main()

