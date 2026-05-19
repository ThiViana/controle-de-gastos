import os
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)

# --- CONFIGURAÇÕES DO SISTEMA ---
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'chave_secreta_super_protegida_123')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///controle_gastos.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- CONFIGURAÇÕES DE E-MAIL (PARA RECUPERAÇÃO DE CONTA) ---
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('EMAIL_USER', 'seu_email@gmail.com')
app.config['MAIL_PASSWORD'] = os.environ.get('EMAIL_PASS', 'sua_senha_de_app_aqui')
app.config['MAIL_DEFAULT_SENDER'] = app.config['MAIL_USERNAME']

db = SQLAlchemy(app)
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# --- SISTEMA DE LOGINS (FLASK-LOGIN) ---
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = "Acesso restrito! Por favor, faça login."
login_manager.login_message_category = "warning"

# --- MODELOS DO BANCO DE DADOS ---

class Usuario(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email_seguranca = db.Column(db.String(120), nullable=False)
    senha_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    forcar_troca_senha = db.Column(db.Boolean, default=False)
    is_active_user = db.Column(db.Boolean, default=True) # True = Ativo, False = Bloqueado
    transacoes = db.relationship('Transacao', backref='criador', lazy=True)

class Transacao(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    descricao = db.Column(db.String(100), nullable=False)
    valor = db.Column(db.Float, nullable=False)
    data = db.Column(db.Date, default=datetime.utcnow)
    tipo = db.Column(db.String(100), nullable=False) # 'Individual' ou 'Partilhado (Criador -> Parceiro)'
    frequencia = db.Column(db.String(50), nullable=False)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return Usuario.query.get(int(user_id))

# Inicialização automática do Banco e do Administrador Mestre
with app.app_context():
    db.create_all()
    # Configuração do Administrador padrão do sistema
    admin_existe = Usuario.query.filter_by(username='admin').first()
    if not admin_existe:
        senha_admin = generate_password_hash('admin1802')
        novo_admin = Usuario(
            username='admin', 
            email_seguranca='tadsviana@gmail.com', 
            senha_hash=senha_admin, 
            is_admin=True,
            is_active_user=True
        )
        db.session.add(novo_admin)
        db.session.commit()

# --- INTERCEPTADOR DE SENHA EXPIRADA ---
@app.before_request
def checar_forcar_troca_senha():
    if current_user.is_authenticated and current_user.forcar_troca_senha:
        if request.endpoint in ['forcar_redefinicao', 'logout', 'static']:
            return
        return redirect(url_for('forcar_redefinicao'))

# --- ROTAS DE AUTENTICAÇÃO ---

@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form['username'].strip().lower()
        email = request.form['email'].strip().lower()
        senha = request.form['senha'].strip()
        
        user_existe = Usuario.query.filter_by(username=username).first()
        if user_existe:
            flash('Este nome de usuário já está sendo usado.', 'danger')
            return redirect(url_for('cadastro'))
            
        novo_usuario = Usuario(username=username, email_seguranca=email, senha_hash=generate_password_hash(senha))
        db.session.add(novo_usuario)
        db.session.commit()
        
        flash('Cadastro realizado com sucesso! Faça login abaixo.', 'success')
        return redirect(url_for('login'))
    return render_template('cadastro.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form['username'].strip().lower()
        senha = request.form['senha'].strip()
        
        user = Usuario.query.filter_by(username=username).first()
        if user and check_password_hash(user.senha_hash, senha):
            if not user.is_active_user:
                flash('Sua conta foi bloqueada pelo administrador do sistema.', 'danger')
                return redirect(url_for('login'))
                
            login_user(user, remember=True)
            return redirect(url_for('home'))
        else:
            flash('Usuário ou senha incorretos.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/forcar-redefinicao', methods=['GET', 'POST'])
@login_required
def forcar_redefinicao():
    if not current_user.forcar_troca_senha:
        return redirect(url_for('home'))
    if request.method == 'POST':
        nova_senha = request.form['nova_senha'].strip()
        current_user.senha_hash = generate_password_hash(nova_senha)
        current_user.forcar_troca_senha = False
        db.session.commit()
        flash('Sua senha foi atualizada com sucesso! Acesso liberado.', 'success')
        return redirect(url_for('home'))
    return render_template('forcar_redefinicao.html')

# --- RECUPERAÇÃO DE CONTA ---

@app.route('/recuperar-senha', methods=['GET', 'POST'])
def recuperar_senha():
    if request.method == 'POST':
        username = request.form['username'].strip().lower()
        user = Usuario.query.filter_by(username=username).first()
        
        if user:
            token = serializer.dumps(username, salt='recuperacao-de-senha-controle')
            link_recuperacao = url_for('redefinir_senha_token', token=token, _external=True)
            
            msg = Message('Recuperação de Senha - Controle de Gastos', recipients=[user.email_seguranca])
            msg.body = f'Para redefinir sua senha, clique no link a seguir (válido por 30 minutos):\n{link_recuperacao}'
            try:
                mail.send(msg)
                flash('Um link de recuperação foi enviado para o e-mail de segurança cadastrado nesta conta.', 'success')
            except:
                flash('Erro ao enviar o e-mail. Verifique as configurações SMTP.', 'danger')
        else:
            flash('Se o usuário estiver cadastrado, um e-mail de recuperação será enviado.', 'success')
    return render_template('recuperar_senha.html')

@app.route('/redefinir-senha/<token>', methods=['GET', 'POST'])
def redefinir_senha_token(token):
    try:
        username = serializer.loads(token, salt='recuperacao-de-senha-controle', max_age=1800)
    except:
        flash('O link de recuperação expirou ou é inválido!', 'danger')
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        nova_senha = request.form['nova_senha'].strip()
        user = Usuario.query.filter_by(username=username).first()
        if user:
            user.senha_hash = generate_password_hash(nova_senha)
            user.forcar_troca_senha = False
            db.session.commit()
            flash('Senha redefinida com sucesso! Faça login.', 'success')
            return redirect(url_for('login'))
    return render_template('redefinir_senha.html')

# --- ÁREA ADMINISTRATIVA ---

@app.route('/admin/usuarios')
@login_required
def painel_admin():
    if not current_user.is_admin:
        flash('Acesso negado!', 'danger')
        return redirect(url_for('home'))
    usuarios = Usuario.query.all()
    return render_template('admin_usuarios.html', usuarios=usuarios)

@app.route('/admin/resetar/<int:user_id>')
@login_required
def admin_resetar_senha(user_id):
    if not current_user.is_admin:
        return redirect(url_for('home'))
    user = Usuario.query.get_or_404(user_id)
    user.senha_hash = generate_password_hash('123456')
    user.forcar_troca_senha = True
    db.session.commit()
    flash(f'A senha de {user.username.capitalize()} foi resetada para "123456". Alteração obrigatória no próximo login!', 'info')
    return redirect(url_for('painel_admin'))

@app.route('/admin/bloquear/<int:user_id>')
@login_required
def admin_bloquear_usuario(user_id):
    if not current_user.is_admin:
        return redirect(url_for('home'))
    user = Usuario.query.get_or_404(user_id)
    if user.is_admin:
        flash('Erro! Não é possível bloquear um administrador.', 'danger')
        return redirect(url_for('painel_admin'))
        
    user.is_active_user = not user.is_active_user
    db.session.commit()
    status = "bloqueado" if not user.is_active_user else "desbloqueado"
    flash(f'O usuário {user.username.capitalize()} foi {status} com sucesso!', 'info')
    return redirect(url_for('painel_admin'))

@app.route('/admin/excluir/<int:user_id>')
@login_required
def admin_excluir_usuario(user_id):
    if not current_user.is_admin:
        return redirect(url_for('home'))
    user = Usuario.query.get_or_404(user_id)
    if user.is_admin:
        flash('Erro! Não é possível excluir o administrador mestre.', 'danger')
        return redirect(url_for('painel_admin'))
        
    # Limpeza em cascata
    Transacao.query.filter_by(usuario_id=user.id).delete()
    db.session.delete(user)
    db.session.commit()
    flash(f'O usuário {user.username.capitalize()} e todos os seus gastos foram apagados.', 'success')
    return redirect(url_for('painel_admin'))

# --- DASHBOARD FINANCEIRO MENSAL PRIVADO ---
@app.route('/')
@login_required
def home():
    hoje = datetime.utcnow()
    mes_selecionado = request.args.get('mes', default=hoje.month, type=int)
    ano_selecionado = request.args.get('ano', default=hoje.year, type=int)

    todas_as_transacoes = Transacao.query.all()
    modelos_fixos = [t for t in todas_as_transacoes if t.frequencia == 'Fixo']
    transacoes_reais_do_mes = [t for t in todas_as_transacoes if t.data.month == mes_selecionado and t.data.year == ano_selecionado]

    # Processamento automático de custos fixos
    clonou_algum = False
    for modelo in modelos_fixos:
        if modelo.data.month == mes_selecionado and modelo.data.year == ano_selecionado:
            continue
        ja_existe_neste_mes = any(t.descricao == modelo.descricao and t.tipo == modelo.tipo and t.usuario_id == modelo.usuario_id for t in transacoes_reais_do_mes)
        if not ja_existe_neste_mes:
            data_do_clone = datetime(ano_selecionado, mes_selecionado, 1)
            novo_clone = Transacao(descricao=modelo.descricao, valor=modelo.valor, tipo=modelo.tipo, frequencia='Fixo', data=data_do_clone, usuario_id=modelo.usuario_id)
            db.session.add(novo_clone)
            clonou_algum = True

    if clonou_algum:
        db.session.commit()
        todas_as_transacoes = Transacao.query.all()
        transacoes_reais_do_mes = [t for t in todas_as_transacoes if t.data.month == mes_selecionado and t.data.year == ano_selecionado]

    transacoes_partilhadas = []
    transacoes_individuais = []

    for t in transacoes_reais_do_mes:
        if t.tipo == 'Individual' and t.usuario_id == current_user.id:
            transacoes_individuais.append(t)
        elif 'Partilhado (' in t.tipo:
            conteudo = t.tipo.replace('Partilhado (', '').replace(')', '')
            criador_gasto, convidado_gasto = [nome.strip().lower() for nome in conteudo.split('->')]
            
            # Só exibe se o usuário logado fizer parte da dupla
            if current_user.username == criador_gasto or current_user.username == convidado_gasto:
                transacoes_partilhadas.append(t)

    resumo_individuais = sum(t.valor for t in transacoes_individuais)
    resumo_partilhados = sum(t.valor for t in transacoes_partilhadas)
    saldo_total = resumo_individuais + resumo_partilhados
    
    total_thiago = resumo_individuais if current_user.username == 'thiago' else 0.0
    total_allan = resumo_individuais if current_user.username == 'allan' else 0.0

    nomes_meses = ["", "Janeiro", "Fevereiro", "Março", "Abril", "Maio", "Junho", "Julho", "Agosto", "Setembro", "Outubro", "Novembro", "Dezembro"]
    mes_nome = nomes_meses[mes_selecionado]
    
    return render_template(
        'index.html', 
        transacoes_partilhadas=transacoes_partilhadas, transacoes_individuais=transacoes_individuais,
        saldo_total=saldo_total, resumo_individuais=resumo_individuais, resumo_partilhados=resumo_partilhados,
        total_thiago=total_thiago, total_allan=total_allan, mes_nome=mes_nome,
        mes_atual=mes_selecionado, ano_atual=ano_selecionado, usuario_logado=current_user.username, e_admin=current_user.is_admin
    )
   
@app.route('/criar', methods=['POST'])
@login_required
def criar():
    descricao = request.form['descricao']
    valor = float(request.form['valor'])
    frequencia = request.form['frequencia']
    categoria = request.form['categoria']

    if categoria == 'Individual':
        tipo_final = 'Individual'
    else:
        parceiro = request.form['parceiro_username'].strip().lower()
        parceiro_existe = Usuario.query.filter_by(username=parceiro).first()
        
        if not parceiro_existe:
            flash(f'Erro! O usuário "{parceiro.capitalize()}" não existe no sistema.', 'danger')
            return redirect(url_for('home'))
        if parceiro == current_user.username:
            flash('Erro! Não é possível partilhar uma conta consigo mesmo.', 'danger')
            return redirect(url_for('home'))
            
        # Formatação automática com iniciais maiúsculas salva direto no banco para a listagem
        tipo_final = f'Partilhado ({current_user.username.capitalize()} -> {parceiro_existe.username.capitalize()})'

    transacao = Transacao(descricao=descricao, valor=valor, tipo=tipo_final, frequencia=frequencia, usuario_id=current_user.id)
    db.session.add(transacao)
    db.session.commit()
    flash('Gasto registrado com sucesso!', 'success')
    return redirect(url_for('home'))

@app.route('/deletar/<int:id>')
@login_required
def deletar(id):
    transacao = Transacao.query.get_or_404(id)
    pode_deletar = False
    
    if transacao.usuario_id == current_user.id:
        pode_deletar = True
    elif 'Partilhado (' in transacao.tipo:
        conteudo = transacao.tipo.replace('Partilhado (', '').replace(')', '')
        nomes_envolvidos = [nome.strip().lower() for nome in conteudo.split('->')]
        if current_user.username in nomes_envolvidos:
            pode_deletar = True

    if pode_deletar:
        db.session.delete(transacao)
        db.session.commit()
        flash('Transação removida.', 'success')
    else:
        flash('Acesso negado para deletar este registro.', 'danger')
        
    return redirect(url_for('home'))

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)