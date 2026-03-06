from . import db
from datetime import datetime

class Scan(db.Model):
    """
    Representa una sesión de evaluación completa.
    Permite comparar el estado de seguridad a lo largo del tiempo.
    """
    __tablename__ = 'scans'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Métricas cuantitativas para el Trabajo de Grado
    total_findings = db.Column(db.Integer, default=0) # Cantidad de vulnerabilidades (V)
    critical_count = db.Column(db.Integer, default=0)
    high_count = db.Column(db.Integer, default=0)
    medium_count = db.Column(db.Integer, default=0)
    low_count = db.Column(db.Integer, default=0)
    
    # Resultado de la fórmula de efectividad
    reduction_percentage = db.Column(db.Float, default=0.0) 
    
    # Relación con los hallazgos detallados
    findings = db.relationship('Finding', backref='scan', lazy=True, cascade="all, delete-orphan")

class Finding(db.Model):
    """
    Guarda el detalle técnico de cada vulnerabilidad detectada por Security Hub.
    Basado en el formato ASFF (AWS Security Finding Format).
    """
    __tablename__ = 'findings'
    
    id = db.Column(db.Integer, primary_key=True) 
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    
    # Información del control CIS
    control_id = db.Column(db.String(50))  # Ej: S3.1, EC2.8
    title = db.Column(db.String(255))
    description = db.Column(db.Text)
    
    # Clasificación del riesgo
    severity = db.Column(db.String(20))    # CRITICAL, HIGH, MEDIUM, LOW
    status = db.Column(db.String(20))      # FAILED, PASSED
    
    # Recurso afectado en AWS
    resource_arn = db.Column(db.String(255)) # El ARN único del recurso
    resource_type = db.Column(db.String(100)) # Ej: AWS::S3::Bucket