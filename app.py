import os
import sqlite3
import hashlib
import secrets
from datetime import datetime
from flask import Flask, request, session, redirect, url_for, render_template, jsonify, g

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'database.db')


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def query(sql, args=(), one=False):
    cur = get_db().execute(sql, args)
    rows = cur.fetchall()
    cur.close()
    return (rows[0] if rows else None) if one else rows


def execute(sql, args=()):
    db = get_db()
    cur = db.execute(sql, args)
    db.commit()
    last_id = cur.lastrowid
    cur.close()
    return last_id


def hash_password(pw):
    return hashlib.sha256(pw.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

def init_db():
    db = sqlite3.connect(DATABASE)
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'student'
    );

    CREATE TABLE IF NOT EXISTS assessments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT,
        teacher_id INTEGER NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (teacher_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS questions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        assessment_id INTEGER NOT NULL,
        question_text TEXT NOT NULL,
        question_type TEXT NOT NULL DEFAULT 'mcq',
        options TEXT,
        correct_answer TEXT NOT NULL,
        topic TEXT NOT NULL,
        difficulty TEXT NOT NULL DEFAULT 'Medium',
        explanation TEXT,
        FOREIGN KEY (assessment_id) REFERENCES assessments(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_id INTEGER NOT NULL,
        assessment_id INTEGER NOT NULL,
        score INTEGER DEFAULT 0,
        percentage REAL DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (student_id) REFERENCES users(id),
        FOREIGN KEY (assessment_id) REFERENCES assessments(id)
    );

    CREATE TABLE IF NOT EXISTS responses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        attempt_id INTEGER NOT NULL,
        question_id INTEGER NOT NULL,
        student_answer TEXT,
        evaluation TEXT DEFAULT 'incorrect',
        error_type TEXT,
        feedback TEXT,
        FOREIGN KEY (attempt_id) REFERENCES attempts(id) ON DELETE CASCADE,
        FOREIGN KEY (question_id) REFERENCES questions(id)
    );

    CREATE TABLE IF NOT EXISTS learning_gaps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        attempt_id INTEGER NOT NULL,
        topic TEXT NOT NULL,
        accuracy REAL DEFAULT 0,
        severity TEXT,
        confidence REAL DEFAULT 0,
        evidence TEXT,
        recommendation TEXT,
        FOREIGN KEY (attempt_id) REFERENCES attempts(id) ON DELETE CASCADE
    );
    """)
    db.commit()
    db.close()


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def current_user():
    if 'user_id' not in session:
        return None
    return query("SELECT * FROM users WHERE id = ?", [session['user_id']], one=True)


def login_required(role=None):
    user = current_user()
    if not user:
        return redirect(url_for('login'))
    if role and user['role'] != role:
        return redirect(url_for('dashboard'))
    return None


# ---------------------------------------------------------------------------
# Learning Gap Detection Engine
# ---------------------------------------------------------------------------

def normalize_answer(text):
    if not text:
        return ""
    return str(text).strip().lower().replace(" ", "").replace(",", ", ")


def evaluate_answer(student_ans, correct_ans, q_type):
    """Return (is_correct, error_type, feedback)."""
    if not student_ans or not student_ans.strip():
        return False, "no_answer", "No answer was provided."

    sa = student_ans.strip().lower()
    ca = correct_ans.strip().lower()

    if q_type == 'mcq':
        is_correct = sa == ca
        if is_correct:
            return True, None, "Correct!"
        return False, "wrong_option", "The selected option does not match the correct answer."

    # Short answer: fuzzy match
    sa_set = set(normalize_answer(student_ans).split(","))
    ca_set = set(normalize_answer(correct_ans).split(","))

    if sa_set == ca_set:
        return True, None, "Correct!"

    # Check for partial match
    overlap = sa_set & ca_set
    if overlap and len(overlap) < len(ca_set):
        missing = ca_set - sa_set
        return False, "partial_answer", f"Partially correct. Missing: {', '.join(missing)}"

    # Detect common error types
    if "-" in correct_ans and "-" not in student_ans:
        return False, "sign_error", "Sign error detected — check negative signs in your answer."
    if any(op in correct_ans for op in ["+", "-"]) and not any(op in student_ans for op in ["+", "-"]):
        return False, "operation_error", "Operation error — check your arithmetic operations."
    if "^" in correct_ans or "²" in correct_ans or "sqrt" in correct_ans.lower():
        return False, "formula_error", "Formula error — review the relevant formula and its application."

    return False, "wrong_answer", "The answer does not match the expected result."


def analyze_learning_gaps(attempt_id):
    """Core engine: group by topic, compute accuracy, severity, confidence, evidence."""
    responses = query("""
        SELECT r.*, q.topic, q.difficulty, q.question_type, q.question_text, q.correct_answer, q.explanation
        FROM responses r
        JOIN questions q ON r.question_id = q.id
        WHERE r.attempt_id = ?
    """, [attempt_id])

    # Group by topic
    topics = {}
    for r in responses:
        topic = r['topic']
        if topic not in topics:
            topics[topic] = {'total': 0, 'correct': 0, 'difficulties': [], 'errors': [], 'questions': []}
        topics[topic]['total'] += 1
        topics[topic]['questions'].append(r)
        if r['evaluation'] == 'correct':
            topics[topic]['correct'] += 1
        else:
            topics[topic]['difficulties'].append(r['difficulty'])
            topics[topic]['errors'].append(r['error_type'])

    gaps = []
    for topic, data in topics.items():
        accuracy = (data['correct'] / data['total']) * 100 if data['total'] > 0 else 0

        # Severity based on accuracy bands
        if accuracy >= 80:
            severity = "Strong"
        elif accuracy >= 60:
            severity = "Needs Practice"
        elif accuracy >= 40:
            severity = "High Risk"
        else:
            severity = "Critical"

        # Confidence: more questions + repeated errors = higher confidence
        num_q = data['total']
        num_errors = len(data['errors'])
        unique_errors = len(set(data['errors']))
        base_confidence = min(50 + num_q * 10, 90)
        if num_errors >= 2:
            base_confidence += 5
        if unique_errors >= 2:
            base_confidence += 3
        confidence = min(base_confidence, 98)

        # Build evidence
        evidence_parts = []
        evidence_parts.append(f"{data['total'] - data['correct']} out of {data['total']} questions were incorrect.")
        if data['difficulties']:
            diff_counts = {}
            for d in data['difficulties']:
                diff_counts[d] = diff_counts.get(d, 0) + 1
            diff_str = ", ".join(f"{d} ({c})" for d, c in diff_counts.items())
            evidence_parts.append(f"Errors occurred in {diff_str} difficulty questions.")
        if unique_errors >= 2:
            error_types_str = ", ".join(set(data['errors']))
            evidence_parts.append(f"Repeated error types detected: {error_types_str}.")
        elif num_errors >= 2 and unique_errors == 1:
            evidence_parts.append(f"Repeated {data['errors'][0]} errors detected.")

        evidence = "\n".join(evidence_parts)

        # Recommendation
        if severity == "Critical":
            recommendation = "1. Start with fundamental concepts and beginner problems\n2. Review core formulas and definitions\n3. Practice 10+ easy problems\n4. Gradually move to medium difficulty\n5. Take an adaptive assessment"
        elif severity == "High Risk":
            recommendation = "1. Review the core concept and key formulas\n2. Practice 5-7 beginner problems\n3. Work through medium difficulty examples\n4. Take a practice assessment"
        elif severity == "Needs Practice":
            recommendation = "1. Review specific problem areas\n2. Practice 3-5 medium problems\n3. Attempt a few hard problems\n4. Reassess understanding"
        else:
            recommendation = "1. Maintain current level\n2. Challenge yourself with harder problems\n3. Help peers who are struggling"

        # Store gap
        execute("""
            INSERT INTO learning_gaps (attempt_id, topic, accuracy, severity, confidence, evidence, recommendation)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, [attempt_id, topic, round(accuracy, 1), severity, confidence, evidence, recommendation])

        gaps.append({
            'topic': topic,
            'accuracy': round(accuracy, 1),
            'severity': severity,
            'confidence': confidence,
            'evidence': evidence,
            'recommendation': recommendation,
            'total': data['total'],
            'correct': data['correct'],
            'errors': data['errors'],
        })

    return gaps


# ---------------------------------------------------------------------------
# Practice question generation (rule-based)
# ---------------------------------------------------------------------------

PRACTICE_BANK = {
    "Algebra": [
        {"q": "Simplify: 3(x + 2) - 2(x - 1)", "type": "short", "options": None, "answer": "3x + 8", "difficulty": "Easy", "explanation": "3x + 6 - 2x + 2 = x + 8"},
        {"q": "Solve for x: 2x + 7 = 15", "type": "short", "options": None, "answer": "4", "difficulty": "Easy", "explanation": "2x = 8, so x = 4"},
        {"q": "Factor: x² - 9", "type": "short", "options": None, "answer": "(x-3)(x+3)", "difficulty": "Medium", "explanation": "Difference of squares: a²-b² = (a-b)(a+b)"},
        {"q": "If f(x) = 2x + 3, what is f(5)?", "type": "short", "options": None, "answer": "13", "difficulty": "Easy", "explanation": "f(5) = 2(5) + 3 = 13"},
        {"q": "Simplify: (2x²)(3x³)", "type": "short", "options": None, "answer": "6x⁵", "difficulty": "Medium", "explanation": "Multiply coefficients and add exponents: 6x^(2+3)"},
    ],
    "Linear Equations": [
        {"q": "Solve: x + 5 = 12", "type": "short", "options": None, "answer": "7", "difficulty": "Easy", "explanation": "x = 12 - 5 = 7"},
        {"q": "Solve: 3x - 4 = 2x + 6", "type": "short", "options": None, "answer": "10", "difficulty": "Medium", "explanation": "3x - 2x = 6 + 4, x = 10"},
        {"q": "Solve the system: x + y = 7, x - y = 1", "type": "short", "options": None, "answer": "x=4, y=3", "difficulty": "Medium", "explanation": "Add equations: 2x = 8, x = 4, y = 3"},
        {"q": "Find the slope of the line through (1,2) and (3,8)", "type": "short", "options": None, "answer": "3", "difficulty": "Medium", "explanation": "slope = (8-2)/(3-1) = 6/2 = 3"},
        {"q": "Solve: 2(x + 3) = 4x - 6", "type": "short", "options": None, "answer": "6", "difficulty": "Hard", "explanation": "2x + 6 = 4x - 6, 12 = 2x, x = 6"},
    ],
    "Quadratic Equations": [
        {"q": "Find the roots of x² - 4x + 4 = 0", "type": "short", "options": None, "answer": "2, 2", "difficulty": "Easy", "explanation": "(x-2)² = 0, so x = 2 (double root)"},
        {"q": "Find the roots of x² + 5x + 6 = 0", "type": "short", "options": None, "answer": "-2, -3", "difficulty": "Easy", "explanation": "Factor: (x+2)(x+3) = 0"},
        {"q": "Find the roots of x² - 7x + 12 = 0", "type": "short", "options": None, "answer": "3, 4", "difficulty": "Medium", "explanation": "Factor: (x-3)(x-4) = 0"},
        {"q": "Using the quadratic formula, solve x² - 5x + 6 = 0", "type": "mcq", "options": "x=2 and x=3|x=1 and x=6|x=-2 and x=-3|x=3 and x=-2", "answer": "x=2 and x=3", "difficulty": "Medium", "explanation": "x = (5 ± √(25-24))/2 = (5±1)/2 = 3 or 2"},
        {"q": "Find the roots of 2x² - 8x + 6 = 0", "type": "short", "options": None, "answer": "1, 3", "difficulty": "Hard", "explanation": "Divide by 2: x² - 4x + 3 = 0, factor: (x-1)(x-3) = 0"},
    ],
    "Functions": [
        {"q": "If f(x) = x² + 1, what is f(3)?", "type": "short", "options": None, "answer": "10", "difficulty": "Easy", "explanation": "f(3) = 9 + 1 = 10"},
        {"q": "If g(x) = 2x - 5, what is g(0)?", "type": "short", "options": None, "answer": "-5", "difficulty": "Easy", "explanation": "g(0) = 2(0) - 5 = -5"},
        {"q": "What is the domain of f(x) = √x?", "type": "mcq", "options": "x ≥ 0|All real numbers|x > 0|x ≤ 0", "answer": "x ≥ 0", "difficulty": "Medium", "explanation": "Square root requires non-negative input"},
        {"q": "If f(x) = x + 2 and g(x) = x², find f(g(3))", "type": "short", "options": None, "answer": "11", "difficulty": "Medium", "explanation": "g(3) = 9, f(9) = 9 + 2 = 11"},
        {"q": "Find f⁻¹(x) if f(x) = 2x + 4", "type": "short", "options": None, "answer": "(x-4)/2", "difficulty": "Hard", "explanation": "y = 2x + 4, swap: x = 2y + 4, y = (x-4)/2"},
    ],
    "Calculus": [
        {"q": "What is the derivative of x²?", "type": "short", "options": None, "answer": "2x", "difficulty": "Easy", "explanation": "Power rule: d/dx(x^n) = nx^(n-1)"},
        {"q": "What is the derivative of 3x + 5?", "type": "short", "options": None, "answer": "3", "difficulty": "Easy", "explanation": "Derivative of constant is 0, derivative of 3x is 3"},
        {"q": "Find the derivative of x³ - 2x² + x", "type": "short", "options": None, "answer": "3x² - 4x + 1", "difficulty": "Medium", "explanation": "Apply power rule to each term"},
        {"q": "What is the integral of 2x dx?", "type": "mcq", "options": "x² + C|2x² + C|x²|2x + C", "answer": "x² + C", "difficulty": "Medium", "explanation": "∫2x dx = x² + C"},
        {"q": "Find the critical point of f(x) = x² - 4x + 3", "type": "short", "options": None, "answer": "x=2", "difficulty": "Hard", "explanation": "f'(x) = 2x - 4 = 0, x = 2"},
    ],
}


def generate_practice_questions(topic, count=5):
    """Generate practice questions for a weak topic: 2 Easy, 2 Medium, 1 Hard."""
    bank = PRACTICE_BANK.get(topic, [])
    if not bank:
        return []

    easy = [q for q in bank if q['difficulty'] == 'Easy']
    medium = [q for q in bank if q['difficulty'] == 'Medium']
    hard = [q for q in bank if q['difficulty'] == 'Hard']

    selected = []
    selected.extend(easy[:2])
    selected.extend(medium[:2])
    selected.extend(hard[:1])

    # If not enough, fill from what's available
    if len(selected) < count:
        remaining = [q for q in bank if q not in selected]
        selected.extend(remaining[:count - len(selected)])

    return selected[:count]


# ---------------------------------------------------------------------------
# Routes — Auth
# ---------------------------------------------------------------------------

@app.route('/')
def index():
    user = current_user()
    if not user:
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        role = request.form.get('role', 'student')

        if not name or not email or not password:
            return render_template('register.html', error='All fields are required.')

        existing = query("SELECT id FROM users WHERE email = ?", [email], one=True)
        if existing:
            return render_template('register.html', error='Email already registered.')

        user_id = execute(
            "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)",
            [name, email, hash_password(password), role]
        )
        session['user_id'] = user_id
        return redirect(url_for('dashboard'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        user = query("SELECT * FROM users WHERE email = ? AND password = ?",
                     [email, hash_password(password)], one=True)
        if not user:
            return render_template('login.html', error='Invalid email or password.')

        session['user_id'] = user['id']
        return redirect(url_for('dashboard'))

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/dashboard')
def dashboard():
    user = current_user()
    if not user:
        return redirect(url_for('login'))

    if user['role'] == 'teacher':
        assessments = query("""
            SELECT a.*, 
                   (SELECT COUNT(*) FROM questions WHERE assessment_id = a.id) as question_count,
                   (SELECT COUNT(*) FROM attempts WHERE assessment_id = a.id) as attempt_count
            FROM assessments a WHERE a.teacher_id = ? ORDER BY a.created_at DESC
        """, [user['id']])

        # Get student results for teacher's assessments
        results = query("""
            SELECT at.*, u.name as student_name, a.title as assessment_title
            FROM attempts at
            JOIN users u ON at.student_id = u.id
            JOIN assessments a ON at.assessment_id = a.id
            WHERE a.teacher_id = ?
            ORDER BY at.created_at DESC
        """, [user['id']])

        return render_template('teacher_dashboard.html', user=user, assessments=assessments, results=results)

    else:
        assessments = query("""
            SELECT a.*, u.name as teacher_name,
                   (SELECT COUNT(*) FROM questions WHERE assessment_id = a.id) as question_count,
                   (SELECT COUNT(*) FROM attempts WHERE at2.student_id = ? AND at2.assessment_id = a.id) as my_attempts
            FROM assessments a
            JOIN users u ON a.teacher_id = u.id
            LEFT JOIN attempts at2 ON at2.assessment_id = a.id AND at2.student_id = ?
            ORDER BY a.created_at DESC
        """, [user['id'], user['id']])

        my_attempts = query("""
            SELECT at.*, a.title as assessment_title
            FROM attempts at
            JOIN assessments a ON at.assessment_id = a.id
            WHERE at.student_id = ?
            ORDER BY at.created_at DESC
        """, [user['id']])

        return render_template('student_dashboard.html', user=user, assessments=assessments, my_attempts=my_attempts)


# ---------------------------------------------------------------------------
# Routes — Teacher: Assessments & Questions
# ---------------------------------------------------------------------------

@app.route('/create_assessment', methods=['GET', 'POST'])
def create_assessment():
    user = current_user()
    if not user:
        return redirect(url_for('login'))
    if user['role'] != 'teacher':
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        if not title:
            return render_template('create_assessment.html', error='Title is required.')

        assessment_id = execute(
            "INSERT INTO assessments (title, description, teacher_id) VALUES (?, ?, ?)",
            [title, description, user['id']]
        )
        return redirect(url_for('add_question', assessment_id=assessment_id))

    return render_template('create_assessment.html', user=user)


@app.route('/assessment/<int:assessment_id>/add_question', methods=['GET', 'POST'])
def add_question(assessment_id):
    user = current_user()
    if not user:
        return redirect(url_for('login'))
    if user['role'] != 'teacher':
        return redirect(url_for('dashboard'))

    assessment = query("SELECT * FROM assessments WHERE id = ?", [assessment_id], one=True)
    if not assessment:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        question_text = request.form.get('question_text', '').strip()
        question_type = request.form.get('question_type', 'mcq')
        options = request.form.get('options', '').strip()
        correct_answer = request.form.get('correct_answer', '').strip()
        topic = request.form.get('topic', '').strip()
        difficulty = request.form.get('difficulty', 'Medium')
        explanation = request.form.get('explanation', '').strip()

        if not question_text or not correct_answer or not topic:
            return render_template('add_question.html', error='Question, correct answer, and topic are required.', assessment=assessment, user=user)

        if question_type == 'mcq' and not options:
            return render_template('add_question.html', error='MCQ questions must have options.', assessment=assessment, user=user)

        execute("""
            INSERT INTO questions (assessment_id, question_text, question_type, options, correct_answer, topic, difficulty, explanation)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, [assessment_id, question_text, question_type, options if question_type == 'mcq' else None,
              correct_answer, topic, difficulty, explanation])

        return redirect(url_for('add_question', assessment_id=assessment_id))

    questions = query("SELECT * FROM questions WHERE assessment_id = ? ORDER BY id", [assessment_id])
    return render_template('add_question.html', assessment=assessment, questions=questions, user=user)


@app.route('/question/<int:question_id>/edit', methods=['GET', 'POST'])
def edit_question(question_id):
    user = current_user()
    if not user:
        return redirect(url_for('login'))
    if user['role'] != 'teacher':
        return redirect(url_for('dashboard'))

    question = query("SELECT * FROM questions WHERE id = ?", [question_id], one=True)
    if not question:
        return redirect(url_for('dashboard'))

    assessment = query("SELECT * FROM assessments WHERE id = ?", [question['assessment_id']], one=True)

    if request.method == 'POST':
        question_text = request.form.get('question_text', '').strip()
        question_type = request.form.get('question_type', 'mcq')
        options = request.form.get('options', '').strip()
        correct_answer = request.form.get('correct_answer', '').strip()
        topic = request.form.get('topic', '').strip()
        difficulty = request.form.get('difficulty', 'Medium')
        explanation = request.form.get('explanation', '').strip()

        execute("""
            UPDATE questions SET question_text=?, question_type=?, options=?, correct_answer=?, topic=?, difficulty=?, explanation=?
            WHERE id=?
        """, [question_text, question_type, options if question_type == 'mcq' else None,
              correct_answer, topic, difficulty, explanation, question_id])

        return redirect(url_for('add_question', assessment_id=question['assessment_id']))

    return render_template('add_question.html', assessment=assessment, questions=[question], user=user, editing=question)


@app.route('/question/<int:question_id>/delete', methods=['POST'])
def delete_question(question_id):
    user = current_user()
    if not user:
        return redirect(url_for('login'))
    if user['role'] != 'teacher':
        return redirect(url_for('dashboard'))

    question = query("SELECT * FROM questions WHERE id = ?", [question_id], one=True)
    if question:
        execute("DELETE FROM questions WHERE id = ?", [question_id])
    return redirect(url_for('add_question', assessment_id=question['assessment_id']))


@app.route('/assessment/<int:assessment_id>/delete', methods=['POST'])
def delete_assessment(assessment_id):
    user = current_user()
    if not user:
        return redirect(url_for('login'))
    if user['role'] != 'teacher':
        return redirect(url_for('dashboard'))

    execute("DELETE FROM questions WHERE assessment_id = ?", [assessment_id])
    execute("DELETE FROM assessments WHERE id = ?", [assessment_id])
    return redirect(url_for('dashboard'))


# ---------------------------------------------------------------------------
# Routes — Student: Take Assessment & Results
# ---------------------------------------------------------------------------

@app.route('/assessment/<int:assessment_id>/take', methods=['GET', 'POST'])
def take_assessment(assessment_id):
    user = current_user()
    if not user:
        return redirect(url_for('login'))
    if user['role'] != 'student':
        return redirect(url_for('dashboard'))

    assessment = query("SELECT * FROM assessments WHERE id = ?", [assessment_id], one=True)
    if not assessment:
        return redirect(url_for('dashboard'))

    questions = query("SELECT * FROM questions WHERE assessment_id = ? ORDER BY id", [assessment_id])
    if not questions:
        return render_template('assessment.html', assessment=assessment, questions=[], user=user, error="This assessment has no questions yet.")

    if request.method == 'POST':
        # Create attempt
        attempt_id = execute(
            "INSERT INTO attempts (student_id, assessment_id, score, percentage) VALUES (?, ?, 0, 0)",
            [user['id'], assessment_id]
        )

        total = len(questions)
        correct_count = 0

        for q in questions:
            field_name = f"q_{q['id']}"
            student_answer = request.form.get(field_name, '').strip()

            is_correct, error_type, feedback = evaluate_answer(
                student_answer, q['correct_answer'], q['question_type']
            )

            evaluation = 'correct' if is_correct else 'incorrect'
            if is_correct:
                correct_count += 1

            execute("""
                INSERT INTO responses (attempt_id, question_id, student_answer, evaluation, error_type, feedback)
                VALUES (?, ?, ?, ?, ?, ?)
            """, [attempt_id, q['id'], student_answer, evaluation, error_type, feedback])

        percentage = round((correct_count / total) * 100, 1) if total > 0 else 0
        execute("UPDATE attempts SET score = ?, percentage = ? WHERE id = ?",
                [correct_count, percentage, attempt_id])

        # Run learning gap analysis
        analyze_learning_gaps(attempt_id)

        return redirect(url_for('report', attempt_id=attempt_id))

    return render_template('assessment.html', assessment=assessment, questions=questions, user=user)


@app.route('/report/<int:attempt_id>')
def report(attempt_id):
    user = current_user()
    if not user:
        return redirect(url_for('login'))

    attempt = query("""
        SELECT at.*, a.title as assessment_title, a.description
        FROM attempts at
        JOIN assessments a ON at.assessment_id = a.id
        WHERE at.id = ?
    """, [attempt_id], one=True)

    if not attempt:
        return redirect(url_for('dashboard'))

    # Security: only the student or a teacher can view
    if user['role'] == 'student' and attempt['student_id'] != user['id']:
        return redirect(url_for('dashboard'))

    gaps = query("SELECT * FROM learning_gaps WHERE attempt_id = ? ORDER BY accuracy ASC", [attempt_id])
    responses = query("""
        SELECT r.*, q.topic, q.difficulty, q.question_type, q.question_text, q.correct_answer, q.explanation
        FROM responses r
        JOIN questions q ON r.question_id = q.id
        WHERE r.attempt_id = ?
    """, [attempt_id])

    # Get previous attempt for comparison
    previous = query("""
        SELECT * FROM attempts WHERE student_id = ? AND assessment_id = ? AND id < ?
        ORDER BY id DESC LIMIT 1
    """, [attempt['student_id'], attempt['assessment_id'], attempt_id], one=True)

    previous_gaps = {}
    if previous:
        prev_gap_rows = query("SELECT * FROM learning_gaps WHERE attempt_id = ?", [previous['id']])
        for pg in prev_gap_rows:
            previous_gaps[pg['topic']] = pg['accuracy']

    return render_template('report.html', attempt=attempt, gaps=gaps, responses=responses,
                          user=user, previous=previous, previous_gaps=previous_gaps)


# ---------------------------------------------------------------------------
# Routes — Practice
# ---------------------------------------------------------------------------

@app.route('/practice/<int:attempt_id>/<topic>')
def practice(attempt_id, topic):
    user = current_user()
    if not user:
        return redirect(url_for('login'))

    attempt = query("SELECT * FROM attempts WHERE id = ?", [attempt_id], one=True)
    if not attempt:
        return redirect(url_for('dashboard'))

    if user['role'] == 'student' and attempt['student_id'] != user['id']:
        return redirect(url_for('dashboard'))

    practice_qs = generate_practice_questions(topic, 5)

    # Get previous accuracy for this topic
    gap = query("SELECT * FROM learning_gaps WHERE attempt_id = ? AND topic = ?", [attempt_id, topic], one=True)
    before_accuracy = gap['accuracy'] if gap else 0

    return render_template('practice.html', topic=topic, questions=practice_qs,
                          attempt=attempt, before_accuracy=before_accuracy, user=user)


@app.route('/practice/submit', methods=['POST'])
def submit_practice():
    user = current_user()
    if not user:
        return redirect(url_for('login'))

    results = []
    correct_count = 0
    total = 0

    for key, value in request.form.items():
        if key.startswith('pq_'):
            idx = int(key.replace('pq_', ''))
            total += 1
            # The question data is embedded in hidden fields
            correct = request.form.get(f'correct_{idx}', '').strip()
            q_text = request.form.get(f'qtext_{idx}', '')
            explanation = request.form.get(f'exp_{idx}', '')
            difficulty = request.form.get(f'diff_{idx}', '')

            is_correct, error_type, feedback = evaluate_answer(value, correct, 'short')
            if is_correct:
                correct_count += 1

            results.append({
                'question': q_text,
                'student_answer': value,
                'correct_answer': correct,
                'is_correct': is_correct,
                'feedback': feedback,
                'explanation': explanation,
                'difficulty': difficulty,
            })

    after_accuracy = round((correct_count / total) * 100, 1) if total > 0 else 0
    before_accuracy = float(request.form.get('before_accuracy', 0))
    improvement = round(after_accuracy - before_accuracy, 1)

    return jsonify({
        'results': results,
        'after_accuracy': after_accuracy,
        'before_accuracy': before_accuracy,
        'improvement': improvement,
        'correct': correct_count,
        'total': total,
    })


# ---------------------------------------------------------------------------
# Demo data seeding
# ---------------------------------------------------------------------------

def seed_demo_data():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row

    # Check if already seeded
    existing = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if existing > 0:
        db.close()
        return

    # Create demo teacher
    teacher_pw = hash_password("teacher123")
    db.execute("INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)",
               ("Demo Teacher", "teacher@demo.com", teacher_pw, "teacher"))
    db.commit()
    teacher_id = db.execute("SELECT id FROM users WHERE email = 'teacher@demo.com'").fetchone()[0]

    # Create demo student
    student_pw = hash_password("student123")
    db.execute("INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)",
               ("Demo Student", "student@demo.com", student_pw, "student"))
    db.commit()
    student_id = db.execute("SELECT id FROM users WHERE email = 'student@demo.com'").fetchone()[0]

    # Create Mathematics assessment
    db.execute("INSERT INTO assessments (title, description, teacher_id) VALUES (?, ?, ?)",
              ("Mathematics Fundamentals", "Comprehensive assessment covering Algebra, Linear Equations, Quadratic Equations, Functions, and Calculus.", teacher_id))
    db.commit()
    assessment_id = db.execute("SELECT id FROM assessments ORDER BY id DESC LIMIT 1").fetchone()[0]

    # Questions with topics and difficulties
    questions = [
        # Algebra
        ("Simplify: 2(x + 3) - (x - 1)", "short", None, "x+7", "Algebra", "Easy", "2x + 6 - x + 1 = x + 7"),
        ("Solve for x: 3x - 5 = 10", "short", None, "5", "Algebra", "Easy", "3x = 15, x = 5"),
        ("Factor: x² - 16", "short", None, "(x-4)(x+4)", "Algebra", "Medium", "Difference of squares"),
        ("Expand: (x + 2)(x + 3)", "short", None, "x²+5x+6", "Algebra", "Medium", "FOIL method"),
        ("Simplify: (x³)/(x²)", "short", None, "x", "Algebra", "Hard", "Subtract exponents: 3-2 = 1"),

        # Linear Equations
        ("Solve: 2x + 3 = 11", "short", None, "4", "Linear Equations", "Easy", "2x = 8, x = 4"),
        ("Solve: x - 7 = -3", "short", None, "4", "Linear Equations", "Easy", "x = -3 + 7 = 4"),
        ("Solve the system: x + y = 5, x - y = 1", "short", None, "x=3,y=2", "Linear Equations", "Medium", "Add: 2x = 6, x = 3, y = 2"),
        ("Find x: 3(2x - 1) = 2(x + 4) + 1", "short", None, "2", "Linear Equations", "Hard", "6x - 3 = 2x + 9, 4x = 12, x = 3"),

        # Quadratic Equations (student will struggle here)
        ("Find the roots of x² - 5x + 6 = 0", "short", None, "2,3", "Quadratic Equations", "Easy", "Factor: (x-2)(x-3) = 0"),
        ("Find the roots of x² + 4x + 4 = 0", "short", None, "-2,-2", "Quadratic Equations", "Easy", "(x+2)² = 0, double root at -2"),
        ("Using the quadratic formula, solve x² - 7x + 12 = 0", "mcq", "x=3 and x=4|x=2 and x=6|x=-3 and x=-4|x=1 and x=12", "x=3 and x=4", "Quadratic Equations", "Medium", "Factor: (x-3)(x-4) = 0"),
        ("Find the roots of x² - 6x + 8 = 0", "short", None, "2,4", "Quadratic Equations", "Medium", "Factor: (x-2)(x-4) = 0"),
        ("Solve: 2x² - 5x - 3 = 0", "short", None, "3,-0.5", "Quadratic Equations", "Hard", "Use quadratic formula: x = (5 ± 7)/4"),

        # Functions (student will struggle here)
        ("If f(x) = x² + 3, find f(2)", "short", None, "7", "Functions", "Easy", "f(2) = 4 + 3 = 7"),
        ("If g(x) = 3x - 1, find g(4)", "short", None, "11", "Functions", "Easy", "g(4) = 12 - 1 = 11"),
        ("If f(x) = x² and g(x) = x + 1, find f(g(2))", "short", None, "9", "Functions", "Medium", "g(2) = 3, f(3) = 9"),
        ("What is the domain of f(x) = 1/x?", "mcq", "x ≠ 0|All real numbers|x > 0|x ≥ 0", "x ≠ 0", "Functions", "Medium", "Cannot divide by zero"),
        ("Find the inverse of f(x) = 3x - 6", "short", None, "(x+6)/3", "Functions", "Hard", "y = 3x - 6, x = (y+6)/3"),

        # Calculus
        ("What is the derivative of 5x²?", "short", None, "10x", "Calculus", "Easy", "Power rule: 2*5x = 10x"),
        ("Find the derivative of x³ + 2x", "short", None, "3x²+2", "Calculus", "Easy", "Power rule on each term"),
        ("What is the derivative of x² - 3x + 1?", "short", None, "2x-3", "Calculus", "Medium", "d/dx(x²) = 2x, d/dx(-3x) = -3"),
        ("Find the integral of 3x² dx", "short", None, "x³+C", "Calculus", "Medium", "Reverse power rule"),
        ("Find the critical point of f(x) = x² - 6x + 5", "short", None, "x=3", "Calculus", "Hard", "f'(x) = 2x - 6 = 0, x = 3"),
    ]

    for q in questions:
        db.execute("""
            INSERT INTO questions (assessment_id, question_text, question_type, options, correct_answer, topic, difficulty, explanation)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (assessment_id, q[0], q[1], q[2], q[3], q[4], q[5], q[6]))

    db.commit()

    # Create a demo attempt for the student with intentional weaknesses
    # Strong in Algebra & Linear Equations, weak in Quadratic Equations & Functions
    db.execute("INSERT INTO attempts (student_id, assessment_id, score, percentage) VALUES (?, ?, 0, 0)",
               (student_id, assessment_id))
    db.commit()
    attempt_id = db.execute("SELECT id FROM attempts ORDER BY id DESC LIMIT 1").fetchone()[0]

    all_questions = db.execute("SELECT * FROM questions WHERE assessment_id = ? ORDER BY id", (assessment_id,)).fetchall()

    # Demo answers: correct for Algebra & Linear Equations & Calculus, wrong for Quadratic & Functions
    demo_answers = {}
    for q in all_questions:
        topic = q['topic']
        if topic == "Algebra":
            demo_answers[q['id']] = q['correct_answer']  # all correct
        elif topic == "Linear Equations":
            demo_answers[q['id']] = q['correct_answer']  # all correct
        elif topic == "Calculus":
            demo_answers[q['id']] = q['correct_answer']  # mostly correct
        elif topic == "Quadratic Equations":
            # Intentionally wrong answers
            demo_answers[q['id']] = "1,1"  # wrong
        elif topic == "Functions":
            # Intentionally wrong answers
            demo_answers[q['id']] = "0"  # wrong

    correct_count = 0
    for q in all_questions:
        ans = demo_answers.get(q['id'], "")
        is_correct, error_type, feedback = evaluate_answer(ans, q['correct_answer'], q['question_type'])
        evaluation = 'correct' if is_correct else 'incorrect'
        if is_correct:
            correct_count += 1
        db.execute("""
            INSERT INTO responses (attempt_id, question_id, student_answer, evaluation, error_type, feedback)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (attempt_id, q['id'], ans, evaluation, error_type, feedback))

    total = len(all_questions)
    percentage = round((correct_count / total) * 100, 1)
    db.execute("UPDATE attempts SET score = ?, percentage = ? WHERE id = ?",
               (correct_count, percentage, attempt_id))
    db.commit()

    # Run learning gap analysis for demo attempt
    # Need to use the app's query/execute functions which use g._database,
    # but we're outside app context. Let's do it manually.
    responses_raw = db.execute("""
        SELECT r.*, q.topic, q.difficulty, q.question_type, q.question_text, q.correct_answer, q.explanation
        FROM responses r
        JOIN questions q ON r.question_id = q.id
        WHERE r.attempt_id = ?
    """, (attempt_id,)).fetchall()

    topics_data = {}
    for r in responses_raw:
        topic = r['topic']
        if topic not in topics_data:
            topics_data[topic] = {'total': 0, 'correct': 0, 'difficulties': [], 'errors': []}
        topics_data[topic]['total'] += 1
        if r['evaluation'] == 'correct':
            topics_data[topic]['correct'] += 1
        else:
            topics_data[topic]['difficulties'].append(r['difficulty'])
            topics_data[topic]['errors'].append(r['error_type'])

    for topic, data in topics_data.items():
        accuracy = (data['correct'] / data['total']) * 100 if data['total'] > 0 else 0
        if accuracy >= 80:
            severity = "Strong"
        elif accuracy >= 60:
            severity = "Needs Practice"
        elif accuracy >= 40:
            severity = "High Risk"
        else:
            severity = "Critical"

        num_q = data['total']
        num_errors = len(data['errors'])
        unique_errors = len(set(data['errors']))
        base_confidence = min(50 + num_q * 10, 90)
        if num_errors >= 2:
            base_confidence += 5
        if unique_errors >= 2:
            base_confidence += 3
        confidence = min(base_confidence, 98)

        evidence_parts = []
        evidence_parts.append(f"{data['total'] - data['correct']} out of {data['total']} questions were incorrect.")
        if data['difficulties']:
            diff_counts = {}
            for d in data['difficulties']:
                diff_counts[d] = diff_counts.get(d, 0) + 1
            diff_str = ", ".join(f"{d} ({c})" for d, c in diff_counts.items())
            evidence_parts.append(f"Errors occurred in {diff_str} difficulty questions.")
        if unique_errors >= 2:
            evidence_parts.append(f"Multiple error types detected: {', '.join(set(data['errors']))}.")
        elif num_errors >= 2:
            evidence_parts.append(f"Repeated {data['errors'][0]} errors detected.")
        evidence = "\n".join(evidence_parts)

        if severity == "Critical":
            recommendation = "1. Start with fundamental concepts and beginner problems\n2. Review core formulas and definitions\n3. Practice 10+ easy problems\n4. Gradually move to medium difficulty\n5. Take an adaptive assessment"
        elif severity == "High Risk":
            recommendation = "1. Review the core concept and key formulas\n2. Practice 5-7 beginner problems\n3. Work through medium difficulty examples\n4. Take a practice assessment"
        elif severity == "Needs Practice":
            recommendation = "1. Review specific problem areas\n2. Practice 3-5 medium problems\n3. Attempt a few hard problems\n4. Reassess understanding"
        else:
            recommendation = "1. Maintain current level\n2. Challenge yourself with harder problems\n3. Help peers who are struggling"

        db.execute("""
            INSERT INTO learning_gaps (attempt_id, topic, accuracy, severity, confidence, evidence, recommendation)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (attempt_id, topic, round(accuracy, 1), severity, confidence, evidence, recommendation))

    db.commit()
    db.close()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    init_db()
    seed_demo_data()
    app.run(debug=True, port=5000)
