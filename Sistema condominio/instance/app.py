from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message as MailMessage
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, DateField, FloatField, TextAreaField, SelectField, BooleanField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Optional
from flask_wtf.file import FileAllowed, MultipleFileField
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from flask_migrate import Migrate
import qrcode
import os
import uuid
import mercadopago

# Configurações
class Config:
    SECRET_KEY = '29100619W@lter'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///site.db'
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'waltervasconcellos@icloud.com'
    MAIL_PASSWORD = 'sua_senha'
    MERCADO_PAGO_ACCESS_TOKEN = 'TEST-8136894985351035-052717-3180990af6260b1025de423fae527ccc-11333471'

# Inicialização do app e extensões
app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)
sdk = mercadopago.SDK(app.config['MERCADO_PAGO_ACCESS_TOKEN'])

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Modelos
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    cpf = db.Column(db.String(11), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    data_de_nascimento = db.Column(db.Date, nullable=False)
    condo_id = db.Column(db.Integer, db.ForeignKey('condo.id'), nullable=True)
    first_login = db.Column(db.Boolean, default=True, nullable=False)

    condo = db.relationship('Condo', back_populates='users', foreign_keys=[condo_id])
    ads = db.relationship('Ad', back_populates='user', cascade='all, delete-orphan')
    lost_and_found = db.relationship('LostAndFound', back_populates='user', cascade='all, delete-orphan')
    conversations = db.relationship('Conversation', back_populates='buyer', foreign_keys='Conversation.buyer_id')
    sold_conversations = db.relationship('Conversation', back_populates='seller', foreign_keys='Conversation.seller_id')

class Condo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    manager_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    users = db.relationship('User', back_populates='condo', foreign_keys=[User.condo_id])
    ads = db.relationship('Ad', back_populates='condo', cascade='all, delete-orphan')
    lost_and_found = db.relationship('LostAndFound', back_populates='condo', cascade='all, delete-orphan')
    manager = db.relationship('User', foreign_keys=[manager_id])

class Ad(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    photos = db.relationship('Photo', back_populates='ad', cascade='all, delete-orphan')
    is_highlighted = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    views = db.Column(db.Integer, default=0)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    condo_id = db.Column(db.Integer, db.ForeignKey('condo.id'), nullable=False)
    plan_id = db.Column(db.Integer, db.ForeignKey('plan.id'), nullable=False)
    is_paid = db.Column(db.Boolean, default=False)
    payment_reference = db.Column(db.String(100), nullable=True)
    payment_qrcode = db.Column(db.String(500), nullable=True)

    user = db.relationship('User', back_populates='ads')
    condo = db.relationship('Condo', back_populates='ads')
    plan = db.relationship('Plan', back_populates='ads')

class Plan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    price = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(200), nullable=True)
    time = db.Column(db.Integer, nullable=False)  # Tempo em horas para destacar o anúncio
    priority = db.Column(db.Integer, nullable=False)  # Prioridade do plano

    ads = db.relationship('Ad', back_populates='plan')

class Photo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    ad_id = db.Column(db.Integer, db.ForeignKey('ad.id'), nullable=False)
    ad = db.relationship('Ad', back_populates='photos')

class Conversation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ad_id = db.Column(db.Integer, db.ForeignKey('ad.id'), nullable=False)
    buyer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    seller_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    messages = db.relationship('Message', back_populates='conversation', cascade='all, delete-orphan')
    ad = db.relationship('Ad')
    buyer = db.relationship('User', foreign_keys=[buyer_id], back_populates='conversations')
    seller = db.relationship('User', foreign_keys=[seller_id], back_populates='sold_conversations')

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey('conversation.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)  # Campo para armazenar o horário da mensagem
    is_read = db.Column(db.Boolean, default=False)  # Campo para armazenar se a mensagem foi lida

    conversation = db.relationship('Conversation', back_populates='messages')
    sender = db.relationship('User')

class LostAndFound(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    found_date = db.Column(db.Date, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    condo_id = db.Column(db.Integer, db.ForeignKey('condo.id'), nullable=False)

    user = db.relationship('User', back_populates='lost_and_found')
    condo = db.relationship('Condo', back_populates='lost_and_found')

# Formulários
class LoginForm(FlaskForm):
    cpf_or_username = StringField('CPF ou Nome de Usuário', validators=[DataRequired()])
    password = PasswordField('Senha', validators=[DataRequired()])
    submit = SubmitField('Entrar')

class ChangePasswordForm(FlaskForm):
    password = PasswordField('Nova Senha', validators=[DataRequired(), EqualTo('confirm', message='As senhas devem coincidir'), Length(min=6)])
    confirm = PasswordField('Repita a Senha')
    submit = SubmitField('Alterar Senha')

class RegistrationForm(FlaskForm):
    username = StringField('Nome de Usuário', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Senha', validators=[DataRequired(), EqualTo('confirm', message='As senhas devem coincidir')])
    confirm = PasswordField('Repita a Senha')
    submit = SubmitField('Registrar')

from flask_wtf.file import FileAllowed, MultipleFileField

class CreateAdForm(FlaskForm):
    title = StringField('Título', validators=[DataRequired()])
    photos = MultipleFileField('Fotos', validators=[FileAllowed(['jpg', 'png', 'jpeg'])])
    description = TextAreaField('Descrição', validators=[DataRequired()])
    price = FloatField('Preço', validators=[DataRequired()])
    plan = SelectField('Plano', choices=[], validators=[DataRequired()])
    submit = SubmitField('Criar Anúncio')

    def __init__(self, *args, **kwargs):
        super(CreateAdForm, self).__init__(*args, **kwargs)
        self.plan.choices = [(plan.id, plan.name) for plan in Plan.query.all()]

class SelectCondoForm(FlaskForm):
    condo = SelectField('Condomínio', choices=[], validators=[DataRequired()])
    submit = SubmitField('Selecionar')

class AdminForm(FlaskForm):
    condo_name = StringField('Nome do Condomínio', validators=[DataRequired()])
    manager_username = StringField('Nome do Síndico', validators=[DataRequired()])
    manager_email = StringField('Email do Síndico', validators=[DataRequired(), Email()])
    manager_password = PasswordField('Senha do Síndico', validators=[Optional(), Length(min=6)])
    manager_cpf = StringField('CPF do Síndico', validators=[DataRequired(), Length(min=11, max=11)])
    manager_data_de_nascimento = DateField('Data de Nascimento do Síndico', validators=[DataRequired()])
    submit = SubmitField('Atualizar Condomínio')

class LostAndFoundForm(FlaskForm):
    item_name = StringField('Nome do Item', validators=[DataRequired()])
    description = TextAreaField('Descrição', validators=[DataRequired()])
    found_date = DateField('Data Encontrada', validators=[DataRequired()])
    submit = SubmitField('Adicionar Item')

class UserForm(FlaskForm):
    first_name = StringField('Nome', validators=[DataRequired()])
    last_name = StringField('Sobrenome', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Senha', validators=[DataRequired(), EqualTo('confirm', message='As senhas devem coincidir')])
    confirm = PasswordField('Repita a Senha')
    cpf = StringField('CPF', validators=[DataRequired(), Length(min=11, max=11)])
    data_de_nascimento = DateField('Data de Nascimento', validators=[DataRequired()])
    submit = SubmitField('Adicionar Usuário')

class SyndicUserForm(FlaskForm):
    nome = StringField('Nome', validators=[DataRequired()])
    sobrenome = StringField('Sobrenome', validators=[DataRequired()])
    cpf = StringField('CPF', validators=[DataRequired(), Length(min=11, max=11)])
    data_de_nascimento = DateField('Data de Nascimento', validators=[DataRequired()])
    submit = SubmitField('Cadastrar')

class FirstLoginForm(FlaskForm):
    data_de_nascimento = DateField('Data de Nascimento', validators=[DataRequired()])
    new_password = PasswordField('Nova Senha', validators=[DataRequired(), Length(min=6)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Atualizar')

class MessageForm(FlaskForm):
    content = TextAreaField('Mensagem', validators=[DataRequired()])
    submit = SubmitField('Enviar')

# Rotas
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter((User.cpf == form.cpf_or_username.data) | (User.username == form.cpf_or_username.data)).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            if user.first_login:
                return redirect(url_for('change_password'))
            return redirect(url_for('select_condo'))
        else:
            flash('Invalid username or password')
    return render_template('login.html', form=form)

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        current_user.password = generate_password_hash(form.password.data)
        current_user.first_login = False
        db.session.commit()
        flash('Senha alterada com sucesso!')
        return redirect(url_for('select_condo'))
    return render_template('change_password.html', form=form)

@app.route('/select_condo', methods=['GET', 'POST'])
@login_required
def select_condo():
    form = SelectCondoForm()
    form.condo.choices = [(c.id, c.name) for c in Condo.query.all()]
    if form.validate_on_submit():
        selected_condo = form.condo.data
        return redirect(url_for('index', condo_id=selected_condo))
    return render_template('select_condo.html', form=form)

@app.route('/<int:condo_id>', methods=['GET'])
@login_required
def index(condo_id):
    ads = Ad.query.filter_by(condo_id=condo_id).order_by(Ad.plan.has(Plan.priority).desc(), Ad.created_at.desc()).all()
    return render_template('index.html', ads=ads, condo_id=condo_id)

@app.route('/<int:condo_id>/create_ad', methods=['GET', 'POST'])
@login_required
def create_ad(condo_id):
    form = CreateAdForm()
    if form.validate_on_submit():
        ad = Ad(
            title=form.title.data,
            description=form.description.data,
            price=form.price.data,
            user_id=current_user.id,
            condo_id=condo_id,
            plan_id=form.plan.data,
            expires_at=datetime.utcnow() + timedelta(weeks=1)
        )
        db.session.add(ad)
        db.session.commit()

        if form.photos.data:
            for file in request.files.getlist('photos'):
                filename = secure_filename(file.filename)
                unique_filename = f"{uuid.uuid4().hex}_{filename}"
                file_path = os.path.join('static/uploads', unique_filename)
                file.save(file_path)
                new_photo = Photo(filename=unique_filename, ad_id=ad.id)
                db.session.add(new_photo)

        db.session.commit()
        flash('Anúncio criado com sucesso')
        return redirect(url_for('index', condo_id=condo_id))
    return render_template('create_ad.html', form=form, condo_id=condo_id)

@app.route('/<int:condo_id>/view_ads', methods=['GET'])
@login_required
def view_ads(condo_id):
    ads = Ad.query.filter_by(condo_id=condo_id).all()
    return render_template('view_ads.html', ads=ads, condo_id=condo_id)

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if current_user.username != 'admin':
        flash('Você não tem acesso a esta página.')
        return redirect(url_for('index'))
    
    form = AdminForm()
    if form.validate_on_submit():
        existing_condo = Condo.query.filter_by(name=form.condo_name.data).first()
        if existing_condo:
            flash('Nome do condomínio já existe. Por favor, escolha um nome diferente.')
            return render_template('admin.html', form=form, condos=Condo.query.all())
        
        condo = Condo(name=form.condo_name.data)
        db.session.add(condo)
        db.session.commit()
        
        manager = User(
            username=form.manager_username.data,
            email=form.manager_email.data,
            password=generate_password_hash(form.manager_password.data),
            cpf=form.manager_cpf.data,
            data_de_nascimento=form.manager_data_de_nascimento.data,
            condo_id=condo.id
        )
        db.session.add(manager)
        db.session.commit()
        
        condo.manager_id = manager.id
        db.session.commit()
        
        flash('Condomínio e síndico criados com sucesso')
    condos = Condo.query.all()
    return render_template('admin.html', form=form, condos=condos)

@app.route('/edit_condo/<int:condo_id>', methods=['GET', 'POST'])
@login_required
def edit_condo(condo_id):
    if current_user.username != 'admin':
        flash('Você não tem acesso a esta página.')
        return redirect(url_for('index'))

    condo = Condo.query.get_or_404(condo_id)
    manager = User.query.filter_by(id=condo.manager_id).first()
    form = AdminForm(obj=manager)
    
    if form.validate_on_submit():
        condo.name = form.condo_name.data
        if manager:
            manager.username = form.manager_username.data
            manager.email = form.manager_email.data
            manager.cpf = form.manager_cpf.data
            manager.data_de_nascimento = form.manager_data_de_nascimento.data
            if form.manager_password.data:
                manager.password = generate_password_hash(form.manager_password.data)
            db.session.commit()
        flash('Condomínio atualizado com sucesso')
        return redirect(url_for('admin'))
    
    form.condo_name.data = condo.name
    if manager:
        form.manager_username.data = manager.username
        form.manager_email.data = manager.email
        form.manager_cpf.data = manager.cpf
        form.manager_data_de_nascimento.data = manager.data_de_nascimento
    return render_template('edit_condo.html', form=form, condo=condo)

@app.route('/delete_condo/<int:condo_id>', methods=['POST'])
@login_required
def delete_condo(condo_id):
    if current_user.username != 'admin':
        flash('Você não tem acesso a esta página.')
        return redirect(url_for('index'))
    
    condo = Condo.query.get_or_404(condo_id)
    db.session.delete(condo)
    db.session.commit()
    flash('Condomínio excluído com sucesso.')
    return redirect(url_for('admin'))

@app.route('/lost_and_found', methods=['GET', 'POST'])
@login_required
def lost_and_found():
    form = LostAndFoundForm()
    if form.validate_on_submit():
        item = LostAndFound(
            item_name=form.item_name.data,
            description=form.description.data,
            found_date=form.found_date.data,
            user_id=current_user.id,
            condo_id=current_user.condo_id
        )
        db.session.add(item)
        db.session.commit()
        flash('Item adicionado aos achados e perdidos')
        return redirect(url_for('lost_and_found'))
    items = LostAndFound.query.filter_by(condo_id=current_user.condo_id).all()
    return render_template('lost_and_found.html', form=form, items=items)

class PlanForm(FlaskForm):
    name = StringField('Nome do Plano', validators=[DataRequired()])
    price = FloatField('Preço', validators=[DataRequired()])
    description = TextAreaField('Descrição', validators=[Optional()])
    submit = SubmitField('Salvar')

@app.route('/admin_plans', methods=['GET', 'POST'])
@app.route('/manage_plans', methods=['GET', 'POST'])
@login_required
def manage_plans():
    form = PlanForm()
    if form.validate_on_submit():
        # Processar o formulário para criar um novo plano
        new_plan = Plan(
            name=form.name.data,
            price=form.price.data,
            description=form.description.data
        )
        db.session.add(new_plan)
        db.session.commit()
        flash('Novo plano adicionado com sucesso.')
        return redirect(url_for('manage_plans'))

    plans = Plan.query.all()
    return render_template('admin_plans.html', form=form, plans=plans)

@app.route('/edit_plan/<int:plan_id>', methods=['GET', 'POST'])
@login_required
def edit_plan(plan_id):
    plan = Plan.query.get_or_404(plan_id)
    form = PlanForm(obj=plan)
    if form.validate_on_submit():
        # Processar o formulário para editar o plano existente
        plan.name = form.name.data
        plan.price = form.price.data
        plan.description = form.description.data
        db.session.commit()
        flash('Plano atualizado com sucesso.')
        return redirect(url_for('manage_plans'))

    return render_template('edit_plan.html', form=form, plan=plan)

@app.route('/delete_plan/<int:plan_id>', methods=['POST'])
@login_required
def delete_plan(plan_id):
    plan = Plan.query.get_or_404(plan_id)
    db.session.delete(plan)
    db.session.commit()
    flash('Plano deletado com sucesso.')
    return redirect(url_for('manage_plans'))

@app.route('/update_plan/<int:plan_id>', methods=['POST'])
@login_required
def update_plan(plan_id):
    plan = Plan.query.get_or_404(plan_id)
    plan.name = request.form.get('name')
    plan.price = request.form.get('price')
    db.session.commit()
    flash('Plano atualizado com sucesso.')
    return redirect(url_for('manage_plans'))






























import mercadopago

app.config['MERCADO_PAGO_ACCESS_TOKEN'] = 'TEST-8136894985351035-052717-3180990af6260b1025de423fae527ccc-11333471'
sdk = mercadopago.SDK(app.config['MERCADO_PAGO_ACCESS_TOKEN'])

from datetime import datetime, timedelta

def create_pix_charge(ad):
    preference_data = {
        "items": [
            {
                "title": ad.title,
                "quantity": 1,
                "unit_price": ad.plan.price
            }
        ],
        "payer": {
            "email": ad.user.email
        },
        "back_urls": {
            "success": f"https://yourdomain.com/ad/{ad.id}",
            "failure": f"https://yourdomain.com/ad/{ad.id}",
            "pending": f"https://yourdomain.com/ad/{ad.id}"
        },
        "notification_url": "https://yourdomain.com/mercadopago/notification",
        "expires": True,
         "expiration_date_from": (datetime.now(brazil_tz)).isoformat(),
        "expiration_date_to": (datetime.now(brazil_tz) + timedelta(minutes=30)).isoformat(),
        "payment_methods": {
            "excluded_payment_types": [
                {
                    "id": "credit_card"
                },
                {
                    "id": "ticket"
                }
            ]
        },
        "external_reference": str(ad.id),
        "description": ad.description
    }

    preference_response = sdk.preference().create(preference_data)
    response = preference_response["response"]
    print("Mercado Pago Response:", response)  # Adicione esta linha para depuração

    # Verificar se 'init_point' existe na resposta
    if 'init_point' in response:
        return response
    else:
        raise ValueError("Response from Mercado Pago does not contain the expected 'init_point' data")

@app.route('/edit_ad/<int:ad_id>', methods=['GET', 'POST'])
@login_required
def edit_ad(ad_id):
    ad = Ad.query.get_or_404(ad_id)
    if ad.user_id != current_user.id:
        flash('Você não tem permissão para editar este anúncio')
        return redirect(url_for('index', condo_id=ad.condo_id))

    form = CreateAdForm(obj=ad)

    if form.validate_on_submit():
        ad.title = form.title.data
        ad.description = form.description.data
        ad.price = form.price.data
        ad.plan_id = form.plan.data

        if form.photos.data:
            for photo in ad.photos:
                file_path = os.path.join('static/uploads', photo.filename)
                if os.path.exists(file_path):
                    os.remove(file_path)
                db.session.delete(photo)
            for file in form.photos.data:
                filename = secure_filename(file.filename)
                unique_filename = f"{uuid.uuid4().hex}_{filename}"
                file_path = os.path.join('static/uploads', unique_filename)
                file.save(file_path)
                new_photo = Photo(filename=unique_filename, ad_id=ad.id)
                db.session.add(new_photo)

        db.session.commit()

        if ad.plan.price > 0:  # Se o plano for pago
            charge_response = create_pix_charge(ad)
            ad.payment_reference = charge_response['id']
            if 'init_point' in charge_response:
                return redirect(charge_response['init_point'])
            else:
                ad.payment_qrcode = None
            db.session.commit()
            return redirect(url_for('pix_payment', ad_id=ad.id))

        flash('Anúncio atualizado com sucesso')
        return redirect(url_for('index', condo_id=ad.condo_id))

    return render_template('edit_ad.html', form=form, ad=ad, condo_id=ad.condo_id)

@app.route('/pix_payment/<int:ad_id>', methods=['GET'])
@login_required
def pix_payment(ad_id):
    ad = Ad.query.get_or_404(ad_id)
    if ad.user_id != current_user.id:
        flash('Você não tem permissão para acessar esta página')
        return redirect(url_for('index', condo_id=ad.condo_id))
    return render_template('pix_payment.html', ad=ad)





from datetime import datetime
import pytz

# Defina o fuso horário do Brasil
brazil_tz = pytz.timezone('America/Sao_Paulo')

# Obtenha a data e hora atual no fuso horário do Brasil
current_time_brazil = datetime.now(brazil_tz)

print("Data e hora no Brasil:", current_time_brazil)





























@app.route('/mercadopago/notification', methods=['POST'])
def mercadopago_notification():
    data = request.json
    ad_id = data['data']['id']
    payment_info = sdk.payment().get(ad_id)
    ad = Ad.query.get_or_404(payment_info['response']['external_reference'])

    if payment_info['response']['status'] == 'approved':
        ad.is_paid = True
        db.session.commit()
        flash('Pagamento confirmado e anúncio atualizado com sucesso')

    return jsonify({'status': 'ok'}), 200

    
@app.route('/delete_ad/<int:ad_id>', methods=['POST'])
@login_required
def delete_ad(ad_id):
    ad = Ad.query.get_or_404(ad_id)
    if ad.user_id != current_user.id:
        flash('Você não tem permissão para excluir este anúncio.')
        return redirect(url_for('my_ads'))
    
    db.session.delete(ad)
    db.session.commit()
    flash('Anúncio excluído com sucesso.')
    return redirect(url_for('my_ads'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/<int:condo_id>/add_user', methods=['GET', 'POST'])
@login_required
def add_user(condo_id):
    if current_user.condo_id != condo_id:
        flash('Você não tem acesso a esta página.')
        return redirect(url_for('index', condo_id=condo_id))
    
    form = UserForm()
    if form.validate_on_submit():
        user = User(
            username=form.first_name.data + ' ' + form.last_name.data,
            email=form.email.data,
            password=generate_password_hash(form.password.data),
            cpf=form.cpf.data,
            data_de_nascimento=form.data_de_nascimento.data,
            condo_id=condo_id
        )
        db.session.add(user)
        db.session.commit()
        flash('Usuário adicionado com sucesso')
        return redirect(url_for('index', condo_id=condo_id))
    return render_template('add_user.html', form=form)

@app.route('/syndic_panel', methods=['GET', 'POST'])
@login_required
def syndic_panel():
    if current_user.id != current_user.condo.manager_id:
        flash('Você não tem acesso a esta página.')
        return redirect(url_for('index'))

    form = SyndicUserForm()
    if form.validate_on_submit():
        user = User(
            username=form.nome.data + ' ' + form.sobrenome.data,
            cpf=form.cpf.data,
            data_de_nascimento=form.data_de_nascimento.data,
            password=generate_password_hash('temporary'),  # senha temporária
            condo_id=current_user.condo_id
        )
        db.session.add(user)
        db.session.commit()
        flash('Usuário cadastrado com sucesso.')
    users = User.query.filter_by(condo_id=current_user.condo_id).all()
    return render_template('syndic_panel.html', form=form, users=users)

@app.route('/first_login', methods=['GET', 'POST'])
def first_login():
    form = FirstLoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(cpf=current_user.cpf).first()
        if user and user.first_login:
            user.password = generate_password_hash(form.new_password.data)
            user.email = form.email.data
            user.first_login = False
            db.session.commit()
            flash('Senha e email atualizados com sucesso.')
            return redirect(url_for('select_condo'))
        else:
            flash('Informações inválidas ou usuário já atualizou suas credenciais.')
    return render_template('first_login.html', form=form)

@app.route('/conversation/<int:ad_id>/<int:buyer_id>', methods=['GET', 'POST'])
@login_required
def conversation(ad_id, buyer_id):
    ad = Ad.query.get_or_404(ad_id)
    seller_id = ad.user_id
    conversation = Conversation.query.filter_by(ad_id=ad_id, buyer_id=buyer_id, seller_id=seller_id).first()
    
    if not conversation:
        conversation = Conversation(ad_id=ad_id, buyer_id=buyer_id, seller_id=seller_id)
        db.session.add(conversation)
        db.session.commit()

    form = MessageForm()
    if form.validate_on_submit():
        message = Message(
            content=form.content.data,
            sender_id=current_user.id,
            conversation_id=conversation.id
        )
        db.session.add(message)
        db.session.commit()
        return redirect(url_for('conversation', ad_id=ad_id, buyer_id=buyer_id))

    # Marcar mensagens como lidas
    messages = Message.query.filter_by(conversation_id=conversation.id).order_by(Message.timestamp).all()
    for message in messages:
        if message.sender_id != current_user.id and not message.is_read:
            message.is_read = True
            db.session.commit()

    return render_template('conversation.html', conversation=conversation, messages=messages, form=form)

class PlanForm(FlaskForm):
    name = StringField('Nome do Plano', validators=[DataRequired()])
    price = FloatField('Preço', validators=[DataRequired()])
    description = TextAreaField('Descrição', validators=[Optional()])
    submit = SubmitField('Salvar')

@app.route('/admin/plans/add', methods=['POST'])
@login_required
def add_plan():
    if current_user.username != 'admin':
        flash('Você não tem acesso a esta página.')
        return redirect(url_for('index'))

    form = PlanForm()
    if form.validate_on_submit():
        # Criar um novo plano com base nos dados do formulário
        new_plan = Plan(
            name=form.name.data,
            price=form.price.data,
            description=form.description.data
        )
        db.session.add(new_plan)
        db.session.commit()
        flash('Novo plano adicionado com sucesso.')
        return redirect(url_for('manage_plans'))
    else:
        flash('Ocorreu um erro ao adicionar o novo plano. Por favor, verifique os dados e tente novamente.', 'error')
        return redirect(url_for('manage_plans'))

@app.route('/chats', methods=['GET'])
@login_required
def chats():
    conversations = (
        db.session.query(Conversation)
        .join(Message)
        .filter((Conversation.seller_id == current_user.id) | (Conversation.buyer_id == current_user.id))
        .all()
    )
    return render_template('chats.html', conversations=conversations)

@app.route('/my_ads', methods=['GET'])
@login_required
def my_ads():
    ads = Ad.query.filter_by(user_id=current_user.id).all()
    return render_template('my_ads.html', ads=ads)

def send_notification(email, subject, message):
    msg = MailMessage(subject, sender=app.config['MAIL_USERNAME'], recipients=[email])
    msg.body = message
    mail.send(msg)

def seed():
    with app.app_context():
        if not User.query.filter_by(username='admin').first():
            admin_user = User(
                username='admin',
                cpf='00000000000',
                email='admin@example.com',
                password=generate_password_hash('admin'),
                data_de_nascimento=datetime(1970, 1, 1).date(),
                first_login=False
            )
            db.session.add(admin_user)
            db.session.commit()
        
        if not Plan.query.first():
            plans = [
                Plan(name='Diamond', price=100.0, description='Plano Diamond', time=48, priority=1),
                Plan(name='Gold', price=50.0, description='Plano Gold', time=24, priority=2),
                Plan(name='Silver', price=20.0, description='Plano Silver', time=12, priority=3),
                Plan(name='Bronze', price=10.0, description='Plano Bronze', time=6, priority=4),
                Plan(name='Free', price=0.0, description='Plano Free', time=0, priority=5)
            ]
            db.session.bulk_save_objects(plans)
            db.session.commit()

@app.route('/ad/<int:ad_id>', methods=['GET'])
@login_required
def view_ad(ad_id):
    ad = Ad.query.get_or_404(ad_id)
    if ad.views is None:
        ad.views = 0
    ad.views += 1  # Incrementa o número de visualizações
    db.session.commit()
    return render_template('view_ad.html', ad=ad)

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        seed()
    app.run(debug=True)
