# classes.py
from datetime import date, datetime
from typing import Any, Dict, List


class Device:
    """
    Représente un appareil avec ses informations de base.
    """

    def __init__(
        self,
        name: str,
        ip: str,
        profile: str,
        site: str,
        last_detected_date: date
    ) -> None:
        """
        Initialise une instance de Device.

        :param name: Le nom de l'appareil.
        :param ip: L'adresse IP de l'appareil.
        :param profile: Le profil associé à l'appareil.
        :param site: Le site où se trouve l'appareil.
        :param last_detected_date: La date à laquelle l'appareil a été détecté pour la dernière fois.
        """
        self.name = name
        self.ip = ip
        self.profile = profile
        self.site = site
        self.last_detected_date = last_detected_date

    def __str__(self) -> str:
        """
        Retourne une représentation textuelle de l'appareil.
        """
        return (
            f"Name: {self.name}\n"
            f"IP: {self.ip}\n"
            f"Profile: {self.profile}\n"
            f"Site: {self.site}\n"
            f"Last Detected Date: {self.last_detected_date}"
        )


class CVE:
    """
    Représente une vulnérabilité identifiée par son identifiant CVE et ses caractéristiques associées.
    """

    def __init__(
        self,
        cve_id: str,
        cvss_score: float,
        description: str,
        publication_date: date,
        cvss_info: Dict[str, Any],
    ) -> None:
        """
        Initialise une instance de CVE.

        :param cve_id: L'identifiant de la vulnérabilité.
        :param cvss_score: Le score CVSS associé à la vulnérabilité.
        :param description: Une description de la vulnérabilité.
        :param publication_date: La date de publication de la vulnérabilité.
        :param cvss_info: Informations complémentaires sur le score CVSS.
        """
        self.cve_id = cve_id
        self.cvss_score = cvss_score
        self.description = description
        self.publication_date = publication_date
        self.cvss_info = cvss_info
        self.devices: List[Device] = []
        self.false_positive: List[Device] = []


    def add_device(self, device: Device) -> None:
        """
        Ajoute un appareil à la liste des appareils affectés par la vulnérabilité.

        :param device: Une instance de Device.
        """

        today = datetime.now()
        delta = today - device.last_detected_date
        if delta.days > 30:
            self.false_positive.append(device)
        else:
            self.devices.append(device)


    def __str__(self) -> str:
        """
        Retourne une représentation textuelle de la vulnérabilité CVE ainsi que les appareils associés.
        """
        devices_str = "\n\n".join(str(device) for device in self.devices)
        fp_str = "\n\n".join(str(device) for device in self.false_positive)
        return (
            f"CVE ID: {self.cve_id}\n"
            f"CVSS Score: {self.cvss_score}\n"
            f"Description: {self.description}\n"
            f"Publication Date: {self.publication_date}\n"
            f"CVSS Info: {self.cvss_info}\n"
            f"Devices: {devices_str}\n"
            f"False Positive: {fp_str}"
        )
