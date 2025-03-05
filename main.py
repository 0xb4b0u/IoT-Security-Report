# main.py
import os
import sys

from api_requests import get_iot_security_data, create_cve_from_data
from report_generator import generate_report


def main():
    # Récupérer la CVE à traiter
    cve_id = input("Entrez l'ID de la CVE (ex: CVE-2015-1635) : ").strip()

    # Récupérer les données IoT Security de la CVE
    cve_data = get_iot_security_data(cve_id)
    if not cve_data:
        print("Aucune donnée IoT Security récupérée pour cette CVE.")
        sys.exit(1)

    # Création de l'objet CVE à partir des données et des détails complémentaires
    cve = create_cve_from_data(cve_data)
    if not cve:
        print("Erreur lors de la création de la CVE.")
        sys.exit(1)

    # Génération du rapport sous format DOCX
    generate_report(cve)
    print(
        f"Le rapport a été généré avec succès dans le dossier : {os.getcwd()}/reports"
    )


if __name__ == "__main__":
    main()
