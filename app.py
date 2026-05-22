import os, calendar
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone

app = Flask(__name__)

# --- CONFIGURAÇÕES DO SISTEMA ---
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'chave_secreta_super_protegida_123')

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
banco_na_raiz = os.path.join(BASE_DIR, 'controle_gastos.db')
banco_na_instance = os.path.join(BASE_DIR, 'instance', 'controle_gastos.db')

# Dá prioridade ao banco original na raiz para não perder dados em produção
if os.path.exists(banco_na_raiz):
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{banco_na_raiz}'
elif os.path.exists(banco_na_instance):
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{banco_na_instance}'
else:
    pasta_instance = os.path.join(BASE_DIR, 'instance')
    if not os.path.exists(pasta_instance):
        os.makedirs(pasta_instance)
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(pasta_instance, "controle_gastos.db")}'

app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'static', 'uploads')
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = "Por favor, faça login para acessar esta página."
login_manager.login_message_category = "info"

# --- MODELOS BANCO DE DADOS ---
class Usuario(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email_seguranca = db.Column(db.String(120), nullable=False)
    senha_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    forcar_troca_senha = db.Column(db.Boolean, default=False)
    is_active_user = db.Column(db.Boolean, default=True)
    nome_exibicao = db.Column(db.String(100), nullable=True)
    foto_perfil = db.Column(db.String(200), nullable=True)

class Transacao(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    descricao = db.Column(db.String(100), nullable=False)
    valor = db.Column(db.Float, nullable=False)
    data = db.Column(db.Date, default=lambda: datetime.now(timezone.utc).date())
    tipo = db.Column(db.String(100), nullable=False)
    frequencia = db.Column(db.String(50), nullable=False)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=False)
    parceiro_username = db.Column(db.String(50), nullable=True)
    porcentagem_criador = db.Column(db.Float, default=50.0)
    porcentagem_parceiro = db.Column(db.Float, default=50.0)
    status_gasto = db.Column(db.String(20), default='Aprovado')
    pago = db.Column(db.Boolean, default=False)
    vencimento = db.Column(db.String(20), nullable=True)
    obs_vencimento = db.Column(db.String(200), nullable=True)

class SolicitacaoExclusao(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    transacao_id = db.Column(db.Integer, db.ForeignKey('transacao.id'), nullable=False)
    solicitante_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=False)
    data_solicitacao = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(Usuario, int(user_id))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def obter_contadores_notificacoes():
    if not current_user.is_authenticated: return 0
    solicitacoes_criacao = Transacao.query.filter_by(parceiro_username=current_user.username, status_gasto='Pendente_Criacao').count()
    id_transacoes_usuario = [t.id for t in Transacao.query.filter((Transacao.usuario_id == current_user.id) | (Transacao.parceiro_username == current_user.username)).all()]
    solicitacoes_exclusao = SolicitacaoExclusao.query.filter(SolicitacaoExclusao.transacao_id.in_(id_transacoes_usuario if id_transacoes_usuario else [0]), SolicitacaoExclusao.solicitante_id != current_user.id).count()
    return solicitacoes_criacao + solicitacoes_exclusao

# ==========================================
# ROTAS DE AUTENTICAÇÃO (LOGIN / LOGOUT)
# ==========================================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        senha = request.form.get('senha') 
        
        usuario = Usuario.query.filter_by(username=username).first()
        
        if usuario and senha and check_password_hash(usuario.senha_hash, senha):
            if not usuario.is_active_user:
                flash('Esta conta está bloqueada pelo administrador.', 'danger')
                return redirect(url_for('login'))
                
            login_user(usuario)
            return redirect(url_for('home'))
        else:
            flash('Usuário ou senha incorretos. Tente novamente.', 'danger')
            
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Você saiu da sua conta com sucesso.', 'success')
    return redirect(url_for('login'))

# ==========================================
# ROTAS DE ADMINISTRAÇÃO (GERENCIAMENTO)
# ==========================================
@app.route('/admin/usuarios', methods=['GET', 'POST'])
@login_required
def gerenciar_usuarios():
    if not current_user.is_admin:
        flash("Acesso restrito! Apenas administradores podem acessar esta página.", "danger")
        return redirect(url_for('home'))

    if request.method == 'POST' and 'delete_user_id' in request.form:
        user_id = request.form.get('delete_user_id')
        user_to_delete = db.session.get(Usuario, user_id)
        
        if user_to_delete:
            if user_to_delete.id == current_user.id:
                flash("Operação cancelada: você não pode excluir sua própria conta admin.", "warning")
            else:
                db.session.delete(user_to_delete)
                db.session.commit()
                flash(f"Usuário '{user_to_delete.username}' removido permanentemente.", "success")
        return redirect(url_for('gerenciar_usuarios'))

    todos_usuarios = Usuario.query.all()
    return render_template('admin_usuarios.html', usuarios=todos_usuarios, total_notificacoes=obter_contadores_notificacoes())


@app.route('/admin/resetar/<int:id>')
@login_required
def resetar_senha(id):
    if not current_user.is_admin:
        flash("Acesso restrito!", "danger")
        return redirect(url_for('home'))
        
    user_to_reset = db.session.get(Usuario, id)
    if user_to_reset:
        if user_to_reset.id == current_user.id:
            flash("Você não pode resetar sua própria senha pelo painel de gerenciamento.", "warning")
        else:
            user_to_reset.senha_hash = generate_password_hash('Mudar123@')
            user_to_reset.forcar_troca_senha = True
            db.session.commit()
            flash(f"A senha de '{user_to_reset.username}' foi resetada para o padrão: Mudar123@", "success")
            
    return redirect(url_for('gerenciar_usuarios'))


@app.route('/admin/bloquear/<int:id>')
@login_required
def alternar_bloqueio(id):
    if not current_user.is_admin:
        flash("Acesso restrito!", "danger")
        return redirect(url_for('home'))
        
    user_to_block = db.session.get(Usuario, id)
    if user_to_block:
        if user_to_block.id == current_user.id:
            flash("Operação negada: você não pode bloquear a si mesmo.", "warning")
        else:
            user_to_block.is_active_user = not user_to_block.is_active_user
            db.session.commit()
            
            status = "bloqueada" if not user_to_block.is_active_user else "desbloqueada"
            categoria = "warning" if not user_to_block.is_active_user else "success"
            flash(f"A conta de '{user_to_block.username}' foi {status}.", categoria)
            
    return redirect(url_for('gerenciar_usuarios'))


# ==========================================
# DASHBOARD PRINCIPAL (CORRIGIDA E INTEGRADA)
# ==========================================
@app.route('/')
@login_required
def home():
    # 1. Filtros de Data (Mês e Ano selecionados)
    hoje = datetime.now(timezone.utc)
    mes_selecionado = request.args.get('mes', default=hoje.month, type=int)
    ano_atual = request.args.get('ano', default=hoje.year, type=int)

    # 2. Busca TODAS as transações aprovadas do usuário
    transacoes = Transacao.query.filter_by(status_gasto='Aprovado').all()
    
    total_pago = 0.0
    total_a_pagar = 0.0
    cat_fixas = 0.0
    cat_variaveis = 0.0
    proximas = []
    historico = []

    # 3. Processa e filtra os dados respeitando a lógica do seu app.py original
    for t in transacoes:
        pertence = False
        valor_meu = 0.0
        
        # Regra de Competência: Despesas Variáveis entram no mês delas. Fixas entram todo mês.
        no_mes_correto = (t.data.month == mes_selecionado and t.data.year == ano_atual) or (t.frequencia == 'Despesas Fixas')

        if no_mes_correto:
            if t.tipo == 'Individual' and t.usuario_id == current_user.id:
                valor_meu = t.valor
                pertence = True
            elif 'Partilhado (' in t.tipo:
                conteudo = t.tipo.replace('Partilhado (', '').replace(')', '')
                try:
                    criador, parceiro = [n.strip().lower() for n in conteudo.split('->')]
                    if current_user.username.lower() == criador:
                        valor_meu = t.valor * (t.porcentagem_criador / 100)
                        pertence = True
                    elif current_user.username.lower() == parceiro:
                        valor_meu = t.valor * (t.porcentagem_parceiro / 100)
                        pertence = True
                except:
                    continue
            
            if pertence:
                # Alimenta o histórico recente
                historico.append({
                    'descricao': t.descricao,
                    'frequencia': t.frequencia,
                    'valor': valor_meu,
                    'pago': t.pago
                })

                # Separa os balanços
                if t.pago:
                    total_pago += valor_meu
                else:
                    total_a_pagar += valor_meu
                    if t.frequencia == 'Despesas Fixas':
                        proximas.append({
                            'descricao': t.descricao,
                            'vencimento': t.vencimento if t.vencimento else 'Mensal',
                            'valor': valor_meu
                        })

                # Soma os grupos do gráfico de pizza
                if t.frequencia == 'Despesas Fixas':
                    cat_fixas += valor_meu
                else:
                    cat_variaveis += valor_meu

    # Define o nome amigável para exibição
    nome_boas_vindas = current_user.nome_exibicao if current_user.nome_exibicao else current_user.username.capitalize()

    # 4. Envia os dados completos e injeta os contadores para destravar o avatar lateral
    return render_template('index.html', 
                           total_pago=total_pago, 
                           total_a_pagar=total_a_pagar,
                           cat_fixas=cat_fixas, 
                           cat_variaveis=cat_variaveis,
                           proximas=proximas[:5], 
                           historico=historico[:5],
                           usuario_logado=nome_boas_vindas,
                           mes_selecionado=mes_selecionado,
                           total_notificacoes=obter_contadores_notificacoes())


# ==========================================
# GESTÃO INDIVIDUAL / PARCERIAS DE DESPESAS
# ==========================================
@app.route('/despesas/<string:escopo>/<string:frequencia>')
@login_required
def listar_despesas(escopo, frequencia):
    hoje = datetime.now(timezone.utc)
    m = request.args.get('mes', default=hoje.month, type=int)
    a = request.args.get('ano', default=hoje.year, type=int)
    
    t_geral, t_pago, t_aberto = 0.0, 0.0, 0.0
    registros_processados = []
    cache_nomes = {}

    if escopo == "individuais":
        if frequencia == "resumo":
            lista = Transacao.query.filter(Transacao.usuario_id == current_user.id, Transacao.tipo == 'Individual', Transacao.status_gasto == 'Aprovado').all()
        else:
            freq_mapeada = "Despesas Fixas" if frequencia == "fixas" else "Despesas Variáveis"
            lista = Transacao.query.filter_by(usuario_id=current_user.id, tipo='Individual', frequencia=freq_mapeada, status_gasto='Aprovado').all()
            
        lista_mes = [t for t in lista if t.data.month == m and t.data.year == a]
        for t in lista_mes:
            t_geral += t.valor
            if t.pago: t_pago += t.valor
            else: t_aberto += t.valor
            registros_processados.append({'transacao': t})
    else:
        if frequencia == "resumo":
            todas = Transacao.query.filter(Transacao.tipo.like('Partilhado (%'), Transacao.status_gasto == 'Aprovado').all()
        else:
            freq_mapeada = "Despesas Fixas" if frequencia == "fixas" else "Despesas Variáveis"
            todas = Transacao.query.filter(Transacao.tipo.like('Partilhado (%'), Transacao.frequencia == freq_mapeada, Transacao.status_gasto == 'Aprovado').all()
            
        lista_mes = [t for t in todas if t.data.month == m and t.data.year == a]
        
        for t in lista_mes:
            conteudo = t.tipo.replace('Partilhado (', '').replace(')', '')
            try:
                criador, parceiro = [n.strip().lower() for n in conteudo.split('->')]
            except:
                continue
            
            if current_user.username.lower() == criador or current_user.username.lower() == parceiro:
                outro = parceiro if current_user.username.lower() == criador else criador
                if outro not in cache_nomes:
                    u = Usuario.query.filter_by(username=outro).first()
                    cache_nomes[outro] = u.nome_exibicao if (u and u.nome_exibicao) else outro.capitalize()
                    
                minha_pct = t.porcentagem_criador if current_user.username.lower() == criador else t.porcentagem_parceiro
                parceiro_pct = t.porcentagem_parceiro if current_user.username.lower() == criador else t.porcentagem_criador
                
                meu_valor = t.valor * (minha_pct / 100)
                parceiro_valor = t.valor * (parceiro_pct / 100)
                
                t_geral += meu_valor
                if t.pago: t_pago += meu_valor
                else: t_aberto += meu_valor

                registros_processados.append({
                    'transacao': t, 'nome_parceiro': cache_nomes[outro],
                    'minha_pct': minha_pct, 'parceiro_pct': parceiro_pct,
                    'meu_valor': meu_valor, 'parceiro_valor': parceiro_valor
                })

    sub_txt = "Resumo Geral" if frequencia == "resumo" else ("Fixas" if frequencia == "fixas" else "Variáveis")
    titulo_tela = f"Despesas Individuais - {sub_txt}" if escopo == "individuais" else f"Despesas Partilhadas - {sub_txt}"
    
    return render_template('visualizar_dados.html', titulo=titulo_tela, dados=registros_processados, escopo=escopo, freq=frequencia, t_geral=t_geral, t_pago=t_pago, t_aberto=t_aberto, total_notificacoes=obter_contadores_notificacoes())

@app.route('/criar', methods=['POST'])
@login_required
def criar():
    descricao = request.form['descricao']
    valor = float(request.form['valor'])
    frequencia = request.form['frequencia']
    categoria = request.form['categoria']
    vencimento = request.form['vencimento'] if frequencia == 'Despesas Fixas' else None
    obs = request.form['obs_vencimento'] if frequencia == 'Despesas Fixas' else None

    if categoria == 'Individual':
        t = Transacao(descricao=descricao, valor=valor, tipo='Individual', frequencia=frequencia, usuario_id=current_user.id, vencimento=vencimento, obs_vencimento=obs)
        db.session.add(t)
    else:
        parceiro = request.form['parceiro_username'].strip().lower()
        pct_c = float(request.form['porcentagem_criador'])
        pct_p = float(request.form['porcentagem_parceiro'])
        p_existe = Usuario.query.filter_by(username=parceiro).first()
        if not p_existe:
            flash("Parceiro não encontrado.", "danger")
            return redirect(url_for('home'))
        t = Transacao(descricao=descricao, valor=valor, tipo=f'Partilhado ({current_user.username.capitalize()} -> {p_existe.username.capitalize()})', frequencia=frequencia, usuario_id=current_user.id, parceiro_username=p_existe.username, porcentagem_criador=pct_c, porcentagem_parceiro=pct_p, status_gasto='Pendente_Criacao', vencimento=vencimento, obs_vencimento=obs)
        db.session.add(t)
        flash("Solicitação enviada ao parceiro!", "info")
    db.session.commit()
    return redirect(url_for('home'))

@app.route('/pagar/<int:id>/<string:escopo>/<string:freq>')
@login_required
def alternar_pagamento(id, escopo, freq):
    t = Transacao.query.get_or_404(id)
    if t.usuario_id == current_user.id or (t.parceiro_username and t.parceiro_username.lower() == current_user.username.lower()):
        t.pago = not t.pago
        db.session.commit()
    return redirect(url_for('listar_despesas', escopo=escopo, frequencia=freq))

@app.route('/deletar/<int:id>/<string:escopo>/<string:freq>')
@login_required
def deletar(id, escopo, freq):
    t = Transacao.query.get_or_404(id)
    if t.tipo == 'Individual' and t.usuario_id == current_user.id:
        db.session.delete(t)
    else:
        sol = SolicitacaoExclusao.query.filter_by(transacao_id=t.id).first()
        if sol and sol.solicitante_id != current_user.id:
            db.session.delete(sol)
            db.session.delete(t)
        else:
            ns = SolicitacaoExclusao(transacao_id=t.id, solicitante_id=current_user.id)
            db.session.add(ns)
    db.session.commit()
    return redirect(url_for('listar_despesas', escopo=escopo, frequencia=freq))

@app.route('/perfil')
@login_required
def ver_perfil():
    return render_template('perfil.html', total_notificacoes=obter_contadores_notificacoes())

@app.route('/perfil/atualizar', methods=['POST'])
@login_required
def atualizar_perfil():
    nome = request.form.get('nome_exibicao', '').strip()
    if nome: current_user.nome_exibicao = nome
    if 'foto_perfil' in request.files:
        f = request.files['foto_perfil']
        if f and f.filename != '' and allowed_file(f.filename):
            ext = f.filename.rsplit('.', 1)[1].lower()
            nome_f = f"user_{current_user.id}.{ext}"
            f.save(os.path.join(app.config['UPLOAD_FOLDER'], nome_f))
            current_user.foto_perfil = nome_f
    db.session.commit()
    flash("Perfil atualizado com sucesso!", "success")
    return redirect(url_for('ver_perfil'))

@app.route('/perfil/senha', methods=['POST'])
@login_required
def alterar_senha():
    antiga = request.form.get('senha_antiga')
    nova = request.form.get('senha_nova')
    if check_password_hash(current_user.senha_hash, antiga):
        current_user.senha_hash = generate_password_hash(nova)
        db.session.commit()
        flash("Senha alterada com sucesso!", "success")
    else:
        flash("Senha anterior incorreta.", "danger")
    return redirect(url_for('ver_perfil'))

@app.route('/solicitacoes')
@login_required
def solicitacoes():
    criacoes_pendentes = Transacao.query.filter_by(parceiro_username=current_user.username, status_gasto='Pendente_Criacao').all()
    criacoes_com_nome = []
    for c in criacoes_pendentes:
        criador_user = db.session.get(Usuario, c.usuario_id)
        nome_criador = criador_user.nome_exibicao if (criador_user and criador_user.nome_exibicao) else criador_user.username.capitalize()
        criacoes_com_nome.append({'gasto': c, 'nome_criador': nome_criador})

    id_transacoes_usuario = [t.id for t in Transacao.query.filter((Transacao.usuario_id == current_user.id) | (Transacao.parceiro_username == current_user.username)).all()]
    exclusoes_pendentes = SolicitacaoExclusao.query.filter(SolicitacaoExclusao.transacao_id.in_(id_transacoes_usuario if id_transacoes_usuario else [0]), SolicitacaoExclusao.solicitante_id != current_user.id).all()
    return render_template('solicitacoes.html', criacoes=criacoes_com_nome, exclusoes=exclusoes_pendentes, total_notificacoes=obter_contadores_notificacoes())

@app.route('/solicitacao/criacao/<int:id>/<string:acao>')
@login_required
def gerenciar_criacao(id, acao):
    t = Transacao.query.get_or_404(id)
    if t.parceiro_username and t.parceiro_username.lower() == current_user.username.lower():
        if acao == 'aceitar': t.status_gasto = 'Aprovado'
        else: db.session.delete(t)
        db.session.commit()
    return redirect(url_for('solicitacoes'))

@app.route('/solicitacao/exclusao/<int:id>/<string:acao>')
@login_required
def gerenciar_exclusao(id, acao):
    solicitacao = SolicitacaoExclusao.query.get_or_404(id)
    transacao = Transacao.query.get(solicitacao.transacao_id)
    if acao == 'aceitar':
        db.session.delete(solicitacao)
        if transacao: db.session.delete(transacao)
    else:
        db.session.delete(solicitacao)
    db.session.commit()
    return redirect(url_for('solicitacoes'))

def atualizar_banco_de_dados():
    db.create_all()
    if not Usuario.query.first():
        senha_criptografada = generate_password_hash('admin1802')
        admin = Usuario(
            username='admin', 
            email_seguranca='admin@seuapp.com', 
            senha_hash=senha_criptografada, 
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()
        print("Usuário Admin padrão criado! (username: admin / senha: admin1802)")

# ==========================================
# ROTA DE CADASTRO (Colocar abaixo da rota de Login)
# ==========================================
@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
        
    if request.method == 'POST':
        username = request.form.get('username').strip().lower()
        email = request.form.get('email').strip()
        senha = request.form.get('senha')
        nome_exibicao = request.form.get('nome_exibicao').strip()
        
        usuario_existe = Usuario.query.filter_by(username=username).first()
        if usuario_existe:
            flash('Este nome de usuário já está em uso.', 'danger')
            return redirect(url_for('cadastro'))
            
        senha_criptografada = generate_password_hash(senha)
        novo_usuario = Usuario(
            username=username,
            email_seguranca=email,
            senha_hash=senha_criptografada,
            nome_exibicao=nome_exibicao if nome_exibicao else None,
            is_admin=False,
            is_active_user=True
        )
        
        db.session.add(novo_usuario)
        db.session.commit()
        
        flash('Conta criada com sucesso! Faça login para entrar.', 'success')
        return redirect(url_for('login'))
        
    return render_template('cadastro.html')

# ==========================================
# ROTA DE RECOVERY (Colocar abaixo do cadastro ou logout)
# ==========================================
@app.route('/esqueci-senha', methods=['GET', 'POST'])
def esqueci_senha():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
        
    if request.method == 'POST':
        username = request.form.get('username').strip()
        email = request.form.get('email').strip()
        
        usuario = Usuario.query.filter_by(username=username, email_seguranca=email).first()
        
        if usuario:
            usuario.forcar_troca_senha = True
            db.session.commit()
            flash('Solicitação enviada! Peça ao Administrador para redefinir sua senha no painel.', 'info')
            return redirect(url_for('login'))
        else:
            flash('Usuário e e-mail de segurança não conferem.', 'danger')
            
    return render_template('esqueci_senha.html')

if __name__ == '__main__':
    with app.app_context():
        atualizar_banco_de_dados()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)