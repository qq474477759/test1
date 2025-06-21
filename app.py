import base64
import hashlib
import logging
import os
import re
import uuid
from collections import Counter
from datetime import datetime, timedelta
from io import BytesIO

import PyPDF2
import requests
import tldextract
import validators
from bs4 import BeautifulSoup
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import generate_password_hash, check_password_hash
from wordcloud import WordCloud

app = Flask(__name__)
app.config.from_pyfile('config.py')
db = SQLAlchemy(app)

# Login Manager Setup
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
login_manager.login_message = 'Please log in to access this page.'
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('WebCrawler')


# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nickname = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    reset_token = db.Column(db.String(100))
    reset_expiry = db.Column(db.DateTime)
    searches = db.relationship('SearchLog', backref='user', lazy=True)


class SearchLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    level = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    pdfs = db.relationship('PDFDocument', backref='search', lazy=True)


class PDFDocument(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    search_id = db.Column(db.Integer, db.ForeignKey('search_log.id'), nullable=False)
    filename = db.Column(db.String(100), nullable=False)
    original_url = db.Column(db.String(500), nullable=False)
    word_stats = db.Column(db.JSON, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    content_hash = db.Column(db.String(32))


# User Loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Helper Functions
def generate_reset_token(email):
    return serializer.dumps(email, salt='password-reset-salt')


def verify_reset_token(token, max_age=60):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=max_age)
        return email
    except:
        return None


# Helper Functions
def get_domain(url):
    """Extract main domain using tldextract"""
    extracted = tldextract.extract(url)
    return f"{extracted.domain}.{extracted.suffix}"


def extract_pdf_stats(pdf_content):
    """Extract word statistics from PDF content"""
    try:
        pdf = PyPDF2.PdfReader(BytesIO(pdf_content))
        text = ""
        for page in pdf.pages:
            text += page.extract_text() + " "

        # Find all words (letters only, no numbers or special chars)
        words = re.findall(r'\b[a-zA-Z]+\b', text.lower())

        # Filter out common stop words and short words
        stop_words = set(['the', 'and', 'of', 'to', 'in', 'a', 'is', 'that', 'for', 'it',
                          'with', 'as', 'this', 'on', 'by', 'be', 'are', 'or', 'an', 'was',
                          'not', 'from', 'have', 'has', 'had', 'will', 'would', 'could', 'should'])
        filtered = [w for w in words if w not in stop_words and len(w) > 3]

        # Count occurrences and get top 10
        word_counts = Counter(filtered).most_common(10)

        # Convert to dictionary
        return dict(word_counts)
    except Exception as e:
        logger.error(f"Error extracting PDF stats: {str(e)}")
        return {}


def generate_content_hash(content):
    """Generate hash for duplicate detection"""
    return hashlib.md5(content).hexdigest()


def generate_wordcloud(text):
    """Generate wordcloud image from text"""
    if not text.strip():
        return None

    # Filter out common words and short words
    words = re.findall(r'\b[a-zA-Z]+\b', text.lower())
    stop_words = set(['the', 'and', 'of', 'to', 'in', 'a', 'is', 'that', 'for', 'it', 'with', 'as', 'this', 'on', 'by'])
    filtered_text = ' '.join([w for w in words if w not in stop_words and len(w) > 3])

    if not filtered_text:
        return None

    wordcloud = WordCloud(width=800, height=400,
                          background_color='white',
                          max_words=100,
                          contour_width=3,
                          contour_color='steelblue',
                          collocations=False)
    wordcloud.generate(filtered_text)

    # Convert to base64 for embedding in HTML
    img = BytesIO()
    wordcloud.to_image().save(img, format='PNG')
    img.seek(0)
    return base64.b64encode(img.getvalue()).decode('utf-8')


def generate_wordcloud_data(pdf_ids):
    """Generate wordcloud from multiple PDFs"""
    text = ""
    for pdf_id in pdf_ids:
        pdf = PDFDocument.query.get(pdf_id)
        if pdf:
            try:
                with open(os.path.join(app.config['UPLOAD_FOLDER'], pdf.filename), 'rb') as f:
                    pdf_content = f.read()
                    pdf_reader = PyPDF2.PdfReader(BytesIO(pdf_content))
                    for page in pdf_reader.pages:
                        text += page.extract_text() + " "
            except Exception as e:
                logger.error(f"Error reading PDF {pdf.filename}: {str(e)}")

    return generate_wordcloud(text)


def crawl_website(url, max_level):
    results = {'pdfs': [], 'error': None}
    visited = set()
    base_domain = get_domain(url)

    def should_crawl(target_url, current_level):
        """Determine if URL should be crawled based on level"""
        if current_level >= max_level:
            return False
        if max_level == 1:
            return False
        if max_level == 2:
            return get_domain(target_url) == base_domain
        return True  # Level 3

    def process_page(page_url, current_level):
        if current_level > max_level or page_url in visited:
            return
        visited.add(page_url)

        try:
            response = requests.get(
                page_url,
                timeout=10,
                headers={'User-Agent': 'Mozilla/5.0'}
            )
            response.raise_for_status()
            soup = BeautifulSoup(response.content, 'html.parser')

            # PDF detection and processing
            for link in soup.find_all('a', href=True):
                href = link['href'].strip()
                if href.lower().endswith('.pdf') or 'pdf' in href.lower():
                    pdf_url = requests.compat.urljoin(page_url, href)
                    if not any(p['url'] == pdf_url for p in results['pdfs']):
                        pdf_content = None
                        try:
                            response = requests.get(
                                pdf_url,
                                timeout=(5, 30),  # 5s connect, 30s read timeout
                                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) WebCrawler/1.0'}
                            )
                            response.raise_for_status()
                            content_type = response.headers.get('Content-Type', '').lower()
                            if 'pdf' in content_type or response.url.lower().endswith('.pdf') and b'%PDF-' in response.content[:4]:
                                pdf_content = response.content
                        except Exception as e:
                            logger.error(f"Failed to download PDF {pdf_url}: {str(e)}")
                            return
                        if pdf_content:
                            content_hash = generate_content_hash(pdf_content)
                            if not PDFDocument.query.filter_by(content_hash=content_hash).first():
                                filename = f"{uuid.uuid4()}.pdf"
                                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                                print(filepath)
                                with open(filepath, 'wb') as f:
                                    f.write(pdf_content)
                                word_stats = extract_pdf_stats(pdf_content)
                                results['pdfs'].append({
                                    'url': pdf_url,
                                    'filename': filename,
                                    'source': page_url,
                                    'level': current_level,
                                    'word_stats': word_stats,
                                    'content_hash': content_hash
                                })

            # Recursive crawling
            if current_level < max_level:
                for link in soup.find_all('a', href=True):
                    next_url = requests.compat.urljoin(page_url, link['href'])
                    if should_crawl(next_url, current_level):
                        process_page(next_url, current_level + 1)

        except Exception as e:
            logger.error(f"Error processing {page_url}: {str(e)}")
            if not results['error']:
                results['error'] = str(e)

    process_page(url, 0)
    return results


# Routes
@app.route('/index')
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        nickname = request.form.get('nickname').strip()
        email = request.form.get('email').strip().lower()
        password = request.form.get('password')

        errors = {}
        if not nickname:
            errors['nickname'] = 'Nickname is required'
        elif User.query.filter_by(nickname=nickname).first():
            errors['nickname'] = 'Nickname already exists'

        if not email or not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
            errors['email'] = 'Valid email is required'
        elif User.query.filter_by(email=email).first():
            errors['email'] = 'Email already registered'

        if not password or len(password) < 8:
            errors['password'] = 'Password must be at least 8 characters'

        if not errors:
            try:
                user = User(
                    nickname=nickname,
                    email=email,
                    password=generate_password_hash(password)
                )
                db.session.add(user)
                db.session.commit()
                flash('Registration successful! Please login.', 'success')
                return redirect(url_for('login'))
            except Exception as e:
                db.session.rollback()
                flash('Registration failed. Please try again.', 'danger')
        else:
            return render_template('register.html', errors=errors, form_data=request.form)

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email').lower()
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('search'))
        else:
            flash('Invalid email or password', 'danger')

    return render_template('login.html')


@login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect(url_for('login', next=request.endpoint))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email').lower()
        user = User.query.filter_by(email=email).first()

        if user:
            token = generate_reset_token(email)
            user.reset_token = token
            user.reset_expiry = datetime.utcnow() + timedelta(seconds=60)
            db.session.commit()

            reset_url = url_for('reset_password', token=token, _external=True)
            msg = Message('Password Reset Request',
                          sender=app.config['MAIL_USERNAME'],
                          recipients=[email])
            msg.body = f'Click to reset your password (valid for 60 seconds): {reset_url}'
            mail.send(msg)

        flash('If an account exists with this email, a reset link has been sent', 'info')
        return redirect(url_for('login'))

    return render_template('forgot_password.html')


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    email = verify_reset_token(token)
    if not email:
        flash('Invalid or expired token', 'danger')
        return redirect(url_for('forgot_password'))

    user = User.query.filter_by(email=email).first()
    if not user or user.reset_token != token or user.reset_expiry < datetime.utcnow():
        flash('Invalid or expired token', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password')
        if len(password) < 8:
            flash('Password must be at least 8 characters', 'danger')
        else:
            user.password = generate_password_hash(password)
            user.reset_token = None
            user.reset_expiry = None
            db.session.commit()
            flash('Password updated successfully! Please login.', 'success')
            return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        nickname = request.form.get('nickname').strip()
        email = request.form.get('email').strip().lower()
        new_password = request.form.get('new_password')

        errors = {}
        if not nickname:
            errors['nickname'] = 'Nickname is required'
        elif nickname != current_user.nickname and User.query.filter_by(nickname=nickname).first():
            errors['nickname'] = 'Nickname already exists'

        if not email or not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
            errors['email'] = 'Valid email is required'
        elif email != current_user.email and User.query.filter_by(email=email).first():
            errors['email'] = 'Email already registered'

        if new_password and len(new_password) < 8:
            errors['new_password'] = 'Password must be at least 8 characters'

        if not errors:
            try:
                current_user.nickname = nickname
                current_user.email = email
                if new_password:
                    current_user.password = generate_password_hash(new_password)
                db.session.commit()
                flash('Profile updated successfully!', 'success')
            except Exception as e:
                db.session.rollback()
                flash('Profile update failed. Please try again.', 'danger')
        else:
            return render_template('profile.html', errors=errors)

    return render_template('profile.html')


@app.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    if request.method == 'GET':
        return render_template('search.html')
    else:
        url = request.form.get('url')
        level = int(request.form.get('level', 1))

        if not validators.url(url):
            flash('Invalid URL format', 'danger')
            return redirect(url_for('search'))

        try:
            crawl_results = crawl_website(url, level)
            if not crawl_results['pdfs']:
                flash('No PDFs found in the crawled pages', 'info')
            else:
                search_log = SearchLog(
                    user_id=current_user.id,
                    url=url,
                    level=level
                )
                db.session.add(search_log)
                db.session.commit()

                for pdf in crawl_results['pdfs']:
                    pdf_doc = PDFDocument(
                        search_id=search_log.id,
                        filename=pdf['filename'],
                        original_url=pdf['url'],
                        word_stats=pdf['word_stats'],
                        content_hash=pdf['content_hash']
                    )
                    db.session.add(pdf_doc)

                db.session.commit()
                flash(f"Found {len(crawl_results['pdfs'])} PDFs", 'success')

            return redirect(url_for('history'))

        except requests.exceptions.RequestException as e:
            flash(f"URL cannot be accessed: {str(e)}", 'danger')
        except Exception as e:
            db.session.rollback()
            flash(f'Crawling failed: {str(e)}', 'danger')

    return render_template('search.html')


@app.route('/history')
@login_required
def history():
    search_term = request.args.get('search_term', '').lower()
    searches = SearchLog.query.filter_by(user_id=current_user.id) \
        .order_by(SearchLog.timestamp.desc()) \
        .all()

    return render_template('history.html',
                           searches=searches,
                           search_term=search_term)


@app.route('/search-pdfs', methods=['GET', 'POST'])
@login_required
def search_pdfs():
    if request.method == 'POST':
        search_term = request.form.get('search_term', '').lower().strip()

        if not search_term:
            flash('Please enter a search term', 'warning')
            return redirect(url_for('search_pdfs'))

        matching_pdfs = []

        for search_log in current_user.searches:
            for pdf in search_log.pdfs:
                # Check if the search term is in the word_stats keys (case insensitive)
                pdf_words = {k.lower(): v for k, v in pdf.word_stats.items()}
                if search_term in pdf_words:
                    matching_pdfs.append({
                        'pdf': pdf,
                        'search_log': search_log,
                        'count': pdf_words.get(search_term, 0)
                    })

        # Sort by count (highest first)
        matching_pdfs.sort(key=lambda x: x['count'], reverse=True)

        return render_template('search_pdfs.html', results=matching_pdfs, search_term=search_term)

    return render_template('search_pdfs.html')


@app.route('/wordcloud', methods=['GET', 'POST'])
@login_required
def wordcloud():
    if request.method == 'POST':
        pdf_ids = request.form.getlist('pdf_ids')
        start_date = request.form.get('start_date')
        end_date = request.form.get('end_date')

        wordcloud_image = None

        if pdf_ids:
            wordcloud_image = generate_wordcloud_data(pdf_ids)
        elif start_date and end_date:
            try:
                start = datetime.strptime(start_date, '%Y-%m-%dT%H:%M')
                end = datetime.strptime(end_date, '%Y-%m-%dT%H:%M')

                # Find PDFs in the date range
                pdfs = PDFDocument.query.join(SearchLog).filter(
                    SearchLog.user_id == current_user.id,
                    PDFDocument.timestamp.between(start, end)
                ).all()

                if pdfs:
                    wordcloud_image = generate_wordcloud_data([pdf.id for pdf in pdfs])
                else:
                    flash('No PDFs found in the selected date range', 'info')
            except ValueError:
                flash('Invalid date format', 'danger')
        else:
            flash('Please select PDFs or a date range', 'warning')

        if wordcloud_image:
            return render_template('wordcloud.html', pdfs=get_user_pdfs(), wordcloud_image=wordcloud_image)

    # Get all user's PDFs for selection
    return render_template('wordcloud.html', pdfs=get_user_pdfs())


def get_user_pdfs():
    """Helper function to get all PDFs for the current user"""
    return PDFDocument.query.join(SearchLog).filter(
        SearchLog.user_id == current_user.id
    ).order_by(PDFDocument.timestamp.desc()).all()


@app.route('/download-pdf/<filename>')
@login_required
def download_pdf(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


if __name__ == '__main__':
    with app.app_context():
        os.makedirs('database', exist_ok=True)
        os.makedirs('pdfs', exist_ok=True)
        db.create_all()
    app.run(debug=True)
