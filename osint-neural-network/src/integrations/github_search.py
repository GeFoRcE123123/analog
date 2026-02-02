import os
from typing import Dict, Any, List, Optional
from github import Github
from dotenv import load_dotenv

load_dotenv()


class GitHubSearch:
    """
    Поиск по GitHub с использованием токена доступа.
    """

    def __init__(self, token: Optional[str] = None):
        self.token = token or os.getenv('GITHUB_TOKEN')
        if not self.token:
            raise ValueError("GITHUB_TOKEN не установлен в .env файле")
        self.client = Github(self.token)

    def search_code(self, query: str, max_results: int = 20) -> List[Dict[str, Any]]:
        """Поиск кода по запросу."""
        results = []
        for i, item in enumerate(self.client.search_code(query)):
            if i >= max_results:
                break
            results.append({
                "repository": item.repository.full_name,
                "path": item.path,
                "html_url": item.html_url
            })
        return results
