import difflib
from .config import Config

def calculate_similarity(str1: str, str2: str) -> float:
    """
    Calculates the similarity ratio between two strings using Levenshtein distance.
    This helps in identifying typo-squatting or ghost packages.
    
    Args:
        str1 (str): The first string (e.g., installed package name).
        str2 (str): The second string (e.g., safe package name).
        
    Returns:
        float: A value between 0.0 and 1.0, where 1.0 is a perfect match.
    """
    return difflib.SequenceMatcher(None, str1, str2).ratio()

def is_safe_package(package_name: str) -> bool:
    """
    Checks if a package is strictly in the known safe list.
    
    Args:
        package_name (str): The name of the package to check.
        
    Returns:
        bool: True if safe, False otherwise.
    """
    return package_name.lower() in Config.SAFE_LIST
