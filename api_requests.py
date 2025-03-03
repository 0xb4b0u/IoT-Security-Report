# api_requests.py
import requests
from datetime import datetime
from typing import Any, Dict, Optional
from os import getenv
from dotenv import load_dotenv

from classes import CVE, Device

load_dotenv()

# Configuration de l'API
BASE_URL = "https://vivalia.iot.paloaltonetworks.com"
API_VERSION = "v4.0"
CUSTOMER_ID = "vivalia"

# En-têtes de la requête API
HEADERS: Dict[str, Any] = {
    "Accept": "application/json",
    "X-Key-Id": getenv("ACCESS_KEY_ID"),
    "X-Access-Key": getenv("SECRET_ACCESS_KEY"),
}


def get_iot_security_data(cve_id: str) -> Optional[Dict[str, Any]]:
    """
    Récupère les données fournies pour une vulnérabilité donnée via l'API de IoT Security.

    :param cve_id: L'identifiant de la CVE.
    :return: Un dictionnaire contenant les données récupérées ou None en cas d'erreur.
    """
    url = f"{BASE_URL}/pub/{API_VERSION}/vulnerability/list?customerid={CUSTOMER_ID}&groupby=device&name={cve_id}"
    try:
        response = requests.get(url, headers=HEADERS)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"Failed to fetch IoT security data: {e}")
        return None


def get_cve_details(cve_id: str) -> Optional[Dict[str, Any]]:
    """
    Récupère les détails d'une vulnérabilité depuis une source externe.

    :param cve_id: L'identifiant de la vulnérabilité (CVE).
    :return: Un dictionnaire contenant la date de publication, la description et les informations CVSS, ou None en cas d'erreur.
    """
    url = f"https://vulnerability.circl.lu/api/cve/{cve_id}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()

        # Extraction et formatage de la date de publication
        pub_date = data.get("cveMetadata", {}).get("datePublished")
        if pub_date:
            pub_date_obj = datetime.strptime(pub_date, "%Y-%m-%dT%H:%M:%S.%fZ")
            pub_date_formatted = pub_date_obj.strftime("%d-%m-%Y")
        else:
            pub_date_formatted = "N/A"

        # Extraction de la description en anglais
        description_value = "N/A"
        descriptions = data.get("containers", {}).get("cna", {}).get("descriptions", [])
        for desc in descriptions:
            if desc.get("lang") == "en":
                description_value = desc.get("value", "N/A")
                break

        # Extraction des informations liées au CVSS dans containers.adp
        cvss_info = {}
        adp_data = data.get("containers", {}).get("adp", [])
        for container in adp_data:
            metrics = container.get("metrics", [])
            for metric in metrics:
                if "cvssV3_1" in metric:
                    cvss_data = metric["cvssV3_1"]
                    cvss_info = {
                        "vecteur_d'attaque": cvss_data.get("attackVector"),
                        "sévérité": cvss_data.get("baseSeverity"),
                        "interaction_utilisateur": cvss_data.get("userInteraction"),
                        "complexité_attaque": cvss_data.get("attackComplexity"),
                        "privilèges_requis": cvss_data.get("privilegesRequired"),
                    }
                    break
            if cvss_info:
                break

        details = {
            "Publication Date": pub_date_formatted,
            "Description": description_value,
            "CVSS Info": cvss_info,
        }
        return details
    except requests.RequestException as e:
        print(f"Failed to fetch CVE details: {e}")
        return None


def create_cve_from_data(data: Dict[str, Any]) -> Optional[CVE]:
    """
    Crée une instance de CVE à partir des données récupérées.

    :param data: Dictionnaire contenant les données des vulnérabilités.
    :return: Une instance de CVE ou None si aucune donnée n'est disponible.
    """
    items = data.get("items", [])
    if not items:
        return None

    first_item = items[0]
    cve_id = first_item.get("vulnerability_name", "N/A")
    details = get_cve_details(cve_id)

    if details is None:
        return None

    cve_instance = CVE(
        cve_id=cve_id,
        cvss_score=first_item.get("cvss_score", "N/A"),
        description=details.get("Description", "N/A"),
        publication_date=details.get("Publication Date"),
        cvss_info=details.get("CVSS Info", {}),
    )

    for item in items:
        try:
            last_detected_str = item.get("last_detected_date", "N/A")
            last_detected_date = datetime.strptime(
                last_detected_str, "%Y-%m-%dT%H:%M:%S.%fZ"
            )
        except (ValueError, TypeError):
            last_detected_date = None

        device = Device(
            name=item.get("name", "N/A"),
            ip=item.get("ip", "N/A"),
            profile=item.get("profile", "N/A"),
            site=item.get("siteName", "N/A"),
            last_detected_date=last_detected_date,
        )
        # Ajout de l'appareil à la liste des appareils affectés par la CVE
        cve_instance.add_device(device)

    return cve_instance
