import os
import dotenv
from datetime import timedelta
from flask import render_template, redirect, url_for, flash, request
from . import db
from .models import Scan, Finding
from flask import current_app as app
import boto3
from botocore.exceptions import ClientError
from .aws_service import get_security_findings, obtener_costos_mes, faltan_credenciales

@app.route('/')
def index():
    todos_los_scans = Scan.query.order_by(Scan.id.asc()).all()
    ultimo_scan = todos_los_scans[-1] if todos_los_scans else None
    primer_scan = todos_los_scans[0] if todos_los_scans else None
    
    labels = [(s.timestamp - timedelta(hours=5)).strftime("%I:%M:%S %p") for s in todos_los_scans[-10:]]
    valores_failed = [s.total_findings for s in todos_los_scans[-10:]]
    valores_passed = [getattr(s, 'passed_count', 0) for s in todos_los_scans[-10:]]
    
    # Diccionario de remediaciones comunes (se usa como base de conocimiento para la UI)
    info_controles = {
        'S3.1': {
            'descripcion': 'El bucket de S3 permite acceso público, lo que puede exponer datos sensibles a internet.',
            'remediacion': 'Ve a la consola de AWS S3 > Selecciona el bucket > Pestaña "Permissions" > Edita "Block public access (bucket settings)" y activa "Block all public access".'
        },
        'IAM.1': {
            'descripcion': 'El usuario Root de la cuenta no tiene habilitado el factor de doble autenticación (MFA).',
            'remediacion': 'Inicia sesión con la cuenta Root > Ve a "Security Credentials" > En la sección MFA, haz clic en "Assign MFA device" y configura un autenticador.'
        },
        'EC2.8': {
            'descripcion': 'La instancia EC2 está usando la versión 1 de los metadatos (IMDSv1), la cual es vulnerable a ataques SSRF.',
            'remediacion': 'En la consola EC2 > Selecciona la instancia > Actions > Instance settings > Modify instance metadata options > Cambia a "V2 (token required)".'
        },
        'VPC.3': {
            'descripcion': 'Los VPC Flow Logs no están habilitados. No hay registro del tráfico de red que entra y sale de la VPC.',
            'remediacion': 'Ve a la consola de VPC > Selecciona tu VPC > Pestaña "Flow logs" > "Create flow log" y configúralo para enviar a CloudWatch o S3.'
        },
        'S3.2': {
            'descripcion': 'El cifrado predeterminado no está habilitado para el bucket de S3.',
            'remediacion': 'Ve a S3 > Selecciona el bucket > Pestaña "Properties" > "Default encryption" > Edita y selecciona "Enable" usando claves administradas por AWS (SSE-S3) o KMS.'
        }
    }
    
    
    # Si detectamos IDs nuevos que no están en el diccionario, les asignamos un mensaje por defecto
    if ultimo_scan and ultimo_scan.findings:
        for finding in ultimo_scan.findings:
            if finding.control_id not in info_controles:
                info_controles[finding.control_id] = {
                    'descripcion': f'Vulnerabilidad detectada: {finding.title}',
                    'remediacion': 'Revisa los detalles de este hallazgo directamente en la consola de AWS Security Hub para aplicar la recomendación oficial.'
                }

    aws_configurado = not faltan_credenciales()
    costo_actual = "0.00"
    
    if aws_configurado:
        costo_data, error_costo = obtener_costos_mes()
        if not error_costo:
            costo_actual = costo_data

    return render_template('index.html', 
                           scan=ultimo_scan, 
                           inicial=primer_scan,
                           labels=labels,
                           valores_failed=valores_failed,
                           valores_passed=valores_passed,
                           info_controles=info_controles,
                           costo=costo_actual,
                           aws_configurado=aws_configurado)

@app.route('/ejecutar-escaneo')
def ejecutar_escaneo():
    # 1. LLAMADA REAL A AWS SECURITY HUB
    hallazgos_reales, error_sh = get_security_findings()
    
    if error_sh:
        # Mostramos una alerta roja y detenemos el escaneo
        flash(error_sh, "danger")
        return redirect(url_for('index'))
    
        
    num_fallos = len(hallazgos_reales)
    
    # 2. CONTADORES REALES DE SEVERIDAD
    criticidad = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFORMATIONAL': 0}
    
    for h in hallazgos_reales:
        sev = h.get('Severity', {}).get('Label', 'INFORMATIONAL')
        if sev in criticidad:
            criticidad[sev] += 1
        else:
            criticidad['INFORMATIONAL'] += 1
            
    # 3. CREAR EL REGISTRO DEL ESCANEO
    nuevo_scan = Scan(
        total_findings=num_fallos,
        critical_count=criticidad['CRITICAL'],
        high_count=criticidad['HIGH'],
        medium_count=criticidad['MEDIUM'],
        low_count=criticidad['LOW']
    )
    
    # Cálculo de métrica de reducción frente al primer escaneo histórico
    primer_scan = Scan.query.order_by(Scan.id.asc()).first()
    if primer_scan and primer_scan.total_findings > 0:
        v_inicial = primer_scan.total_findings
        v_final = num_fallos
        nuevo_scan.reduction_percentage = ((v_inicial - v_final) / v_inicial) * 100
    else:
        nuevo_scan.reduction_percentage = 0.0
        
    db.session.add(nuevo_scan)
    db.session.commit()

    # 4. GUARDAR LOS HALLAZGOS REALES (FINDINGS)
    for h in hallazgos_reales:
        # Security Hub entrega IDs complejos (ej. arn:aws:securityhub:.../cis-aws-foundations-benchmark/v/1.2.0/1.4)
        # Intentamos extraer el final (ej. 1.4) o el SecurityControlId
        control_id = h.get('Compliance', {}).get('SecurityControlId', 'N/A')
        if control_id == 'N/A':
            gen_id = h.get('GeneratorId', '')
            control_id = gen_id.split('/')[-1] if '/' in gen_id else 'Desconocido'
            
        # Obtenemos el ARN real del recurso afectado (Bucket, Instancia, IAM Role, etc.)
        recursos = h.get('Resources', [])
        resource_arn = recursos[0].get('Id', 'ARN no disponible') if recursos else 'ARN no disponible'

        f = Finding(
            scan_id=nuevo_scan.id,
            control_id=control_id,
            title=h.get('Title', 'Vulnerabilidad sin título'),
            status=h.get('Compliance', {}).get('Status', 'FAILED'),
            severity=h.get('Severity', {}).get('Label', 'INFORMATIONAL'),
            resource_arn=resource_arn
        )
        db.session.add(f)
        
    db.session.commit()
    flash(f"Escaneo de AWS completado: Se detectaron {num_fallos} recursos vulnerables.", "success")
    return redirect(url_for('index'))

@app.route('/configuracion-aws')
def configuracion_aws():
    estado_conexion = "Desconectado"
    cuenta_id = "N/A"
    usuario_arn = "N/A"
    
    # Validamos si las variables existen realmente en el entorno
    llaves_existen = not faltan_credenciales()

    if not llaves_existen:
        return render_template('configuracion.html', 
                               estado=estado_conexion, 
                               cuenta=cuenta_id, 
                               arn=usuario_arn,
                               llaves_existen=llaves_existen)
    
    try:
        sts_client = boto3.client(
            'sts',
            aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
            region_name=os.getenv('AWS_DEFAULT_REGION', 'us-east-1')
        )
        identidad = sts_client.get_caller_identity()
        
        estado_conexion = "Conectado"
        cuenta_id = identidad.get('Account')
        usuario_arn = identidad.get('Arn')
        
    except ClientError as e:
        estado_conexion = "Credenciales Inválidas"
        flash("Las credenciales ingresadas son inválidas o no tienen permisos.", "danger")
    except Exception as e:
        estado_conexion = f"Error: {e}"

    return render_template('configuracion.html', 
                           estado=estado_conexion, 
                           cuenta=cuenta_id, 
                           arn=usuario_arn,
                           llaves_existen=llaves_existen)

@app.context_processor
def inject_aws_status():
    estado_aws = "desconectado"
    
    if not faltan_credenciales():
        try:
            # Hacemos la validación real con STS
            sts_client = boto3.client(
                'sts',
                aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
                aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
                region_name=os.getenv('AWS_DEFAULT_REGION', 'us-east-1')
            )
            sts_client.get_caller_identity()
            # Si pasa la línea anterior, las credenciales son 100% válidas
            estado_aws = "conectado"
        except ClientError:
            # Boto3 rechaza las credenciales
            estado_aws = "error_credenciales"
        except Exception:
            # Falla la red u otro error
            estado_aws = "error_red"
            
    # Retornamos la variable 'estado_aws' para usarla en el HTML
    return dict(estado_aws=estado_aws)

# ==========================================
# RUTA PARA DESCONECTAR AWS
# ==========================================
@app.route('/desconectar-aws', methods=['POST'])
def desconectar_aws():
    try:
        # Buscamos el archivo .env
        env_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '.env'))
        
        # Vaciamos las variables físicas en el archivo
        if os.path.exists(env_path):
            dotenv.set_key(env_path, 'AWS_ACCESS_KEY_ID', '')
            dotenv.set_key(env_path, 'AWS_SECRET_ACCESS_KEY', '')
        
        # Borramos las variables de la memoria viva de Python
        os.environ.pop('AWS_ACCESS_KEY_ID', None)
        os.environ.pop('AWS_SECRET_ACCESS_KEY', None)
        
        flash("Se ha desconectado el entorno de AWS y las credenciales fueron removidas.", "info")
    except Exception as e:
        flash(f"Ocurrió un error al intentar desconectar: {e}", "danger")
        
    return redirect(url_for('configuracion_aws'))

@app.route('/roles-permisos')
def roles_permisos():
    return render_template('roles.html')

@app.route('/mapa-entorno')
def mapa_entorno():
    return render_template('mapa.html')

@app.route('/inventario-s3')
def auditoria_s3():
    return render_template('s3.html')

@app.route('/auditoria-ec2')
def auditoria_ec2():
    return render_template('ec2.html')

@app.route('/auditoria-rds')
def auditoria_rds():
    return render_template('rds.html')

@app.route('/auditoria-vpc')
def auditoria_vpc():
    return render_template('vpc.html')

@app.route('/auditoria-lambda')
def auditoria_lambda():
    return render_template('lambda.html')

@app.route('/auditoria-cloudwatch')
def auditoria_cloudwatch():
    return render_template('cloudwatch.html')

@app.route('/auditoria-route53')
def auditoria_route53():
    return render_template('route53.html')

@app.route('/guardar-credenciales', methods=['POST'])
def guardar_credenciales():
    access_key = request.form.get('aws_access_key')
    secret_key = request.form.get('aws_secret_key')
    
    if not access_key or not secret_key:
        flash("Ambas credenciales son obligatorias.", "danger")
        return redirect(url_for('configuracion_aws'))
        
    try:
        env_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '.env'))
        
        if not os.path.exists(env_path):
            with open(env_path, 'w') as f:
                f.write("")
                
        dotenv.set_key(env_path, 'AWS_ACCESS_KEY_ID', access_key)
        dotenv.set_key(env_path, 'AWS_SECRET_ACCESS_KEY', secret_key)
        
        if not os.getenv('AWS_DEFAULT_REGION'):
            dotenv.set_key(env_path, 'AWS_DEFAULT_REGION', 'us-east-1')
            os.environ['AWS_DEFAULT_REGION'] = 'us-east-1'
            
        os.environ['AWS_ACCESS_KEY_ID'] = access_key
        os.environ['AWS_SECRET_ACCESS_KEY'] = secret_key
        
        flash("Credenciales guardadas correctamente. Tu dashboard ya está conectado a AWS.", "success")
        
    except Exception as e:
        flash(f"Ocurrió un error al guardar las credenciales: {e}", "danger")
        
    return redirect(url_for('configuracion_aws'))