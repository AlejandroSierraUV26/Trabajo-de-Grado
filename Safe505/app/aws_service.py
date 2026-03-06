import boto3
import os
from datetime import date
from dotenv import load_dotenv
from botocore.exceptions import ClientError

# Cargamos las variables del .env
load_dotenv()

def faltan_credenciales():
    """
    Verifica si las variables de entorno básicas de AWS están definidas.
    Retorna True si falta alguna, False si están configuradas.
    """
    access_key = os.getenv('AWS_ACCESS_KEY_ID')
    secret_key = os.getenv('AWS_SECRET_ACCESS_KEY')
    
    # Si las variables son None o cadenas vacías, consideramos que faltan
    if not access_key or not secret_key:
        return True
    return False

def obtener_costos_mes():
    """
    Se conecta a AWS Cost Explorer.
    Retorna: (costo_float, mensaje_de_error)
    """
    # 1. Validación de credenciales antes de hacer nada
    if faltan_credenciales():
        return None, "⚠️ Las credenciales de AWS no están configuradas. Por favor, define AWS_ACCESS_KEY_ID y AWS_SECRET_ACCESS_KEY (próximamente desde la vista de Conexión AWS)."
    try:
        ce_client = boto3.client(
            'ce',
            region_name='us-east-1',
            aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY')
        )
        
        hoy = date.today()
        primer_dia_mes = hoy.replace(day=1)
        start_date = primer_dia_mes.strftime('%Y-%m-%d')
        end_date = hoy.strftime('%Y-%m-%d')
        
        if start_date == end_date:
            return "0.00", None

        response = ce_client.get_cost_and_usage(
            TimePeriod={'Start': start_date, 'End': end_date},
            Granularity='MONTHLY',
            Metrics=['UnblendedCost']
        )
        
        costo_total = response['ResultsByTime'][0]['Total']['UnblendedCost']['Amount']
        return round(float(costo_total), 2), None

    except ClientError as e:
        error_msg = e.response['Error']['Message']
        return None, f"Error de permisos en AWS Cost Explorer: {error_msg}"
    except Exception as e:
        return None, f"Error obteniendo costos: {e}"

def get_security_findings():
    """
    Se conecta a AWS Security Hub.
    Retorna: (lista_hallazgos, mensaje_de_error)
    """
    if faltan_credenciales():
         return None, "⚠️ Credenciales de AWS no detectadas. Configura tus accesos para poder ejecutar el escaneo."
    try:
        client = boto3.client(
            'securityhub',
            aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
            region_name=os.getenv('AWS_DEFAULT_REGION')
        )

        filters = {
            'ComplianceStatus': [{'Value': 'FAILED', 'Comparison': 'EQUALS'}],
            'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}]
        }

        response = client.get_findings(Filters=filters, MaxResults=10)
        return response.get('Findings', []), None

    except ClientError as e:
        error_msg = e.response['Error']['Message']
        return None, f"Acceso Denegado en Security Hub: {error_msg}"
    except Exception as e:
        return None, f"Error conectando con AWS: {e}"