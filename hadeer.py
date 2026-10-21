import hashlib
import hmac
import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

from flask import Flask, g, jsonify, render_template, request, send_from_directory, session


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("HADEER_DB_PATH", BASE_DIR / "school_database.db"))
LOGO_DIR = BASE_DIR / "s3ar.img"
LOGO_NAME = "800482344_18620431918042287_6726415875650701915_n.jpg"

DEPARTMENTS = (
    "اللغة العربية",
    "الرياضيات",
    "التربية الإسلامية",
    "التربية البدنية",
    "اللغة الإنجليزية",
    "الأحياء",
    "الفيزياء",
    "الكيمياء",
    "الحاسوب",
    "الجيولوجيا",
    "اللغة الفرنسية",
    "الإحصاء",
    "الجغرافيا",
    "الفلسفة",
    "علم النفس",
    "التاريخ",
    "التربية الفنية",
    "التربية الموسيقية",
    "الدستور",
    "الاقتصاد المنزلي",
    "التوعية المرورية",
)


class ApiError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def _password_hash(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return f"{salt.hex()}:{digest.hex()}"


def _password_matches(password, encoded):
    try:
        salt_hex, _ = encoded.split(":", 1)
        candidate = _password_hash(password, bytes.fromhex(salt_hex))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(candidate, encoded)


def normalize_civil_id(value):
    digits = str.maketrans("٠١٢٣٤٥٦٧٨٩۰۱۲۳۴۵۶۷۸۹", "01234567890123456789")
    return str(value or "").strip().translate(digits)


def valid_civil_id(value):
    return len(value) == 12 and value.isascii() and value.isdigit()


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(
            current_app_config_path(),
            timeout=10,
            detect_types=sqlite3.PARSE_DECLTYPES,
        )
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        g.db.execute("PRAGMA busy_timeout = 10000")
    return g.db


def current_app_config_path():
    from flask import current_app

    return current_app.config["DATABASE"]


def _table_exists(connection, name):
    return connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (name,),
    ).fetchone() is not None


def _columns(connection, name):
    return {row["name"] for row in connection.execute(f"PRAGMA table_info({name})")}


def initialize_database(database_path):
    connection = sqlite3.connect(database_path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        for table in ("teachers", "students"):
            if _table_exists(connection, table) and "school_id" not in _columns(connection, table):
                legacy = f"legacy_{table}"
                if not _table_exists(connection, legacy):
                    connection.execute(f"ALTER TABLE {table} RENAME TO {legacy}")
                else:
                    connection.execute(f"DROP TABLE {table}")

        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS schools (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                civil_id TEXT NOT NULL UNIQUE,
                school_name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS classes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                school_id INTEGER NOT NULL REFERENCES schools(id) ON DELETE CASCADE,
                grade_name TEXT NOT NULL,
                section_name TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(school_id, grade_name, section_name)
            );

            CREATE TABLE IF NOT EXISTS teachers (
                school_id INTEGER NOT NULL REFERENCES schools(id) ON DELETE CASCADE,
                civil_id TEXT NOT NULL,
                full_name TEXT NOT NULL,
                department TEXT NOT NULL,
                is_department_head INTEGER NOT NULL DEFAULT 0 CHECK(is_department_head IN (0, 1)),
                PRIMARY KEY(school_id, civil_id)
            );

            CREATE TABLE IF NOT EXISTS teacher_classes (
                school_id INTEGER NOT NULL,
                teacher_civil_id TEXT NOT NULL,
                class_id INTEGER NOT NULL,
                PRIMARY KEY(school_id, teacher_civil_id, class_id),
                FOREIGN KEY(school_id, teacher_civil_id)
                    REFERENCES teachers(school_id, civil_id) ON DELETE CASCADE,
                FOREIGN KEY(class_id) REFERENCES classes(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS students (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                school_id INTEGER NOT NULL REFERENCES schools(id) ON DELETE CASCADE,
                class_id INTEGER NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
                full_name TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(school_id, class_id, full_name)
            );

            CREATE TABLE IF NOT EXISTS attendance_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                school_id INTEGER NOT NULL REFERENCES schools(id) ON DELETE CASCADE,
                report_type TEXT NOT NULL CHECK(report_type IN ('student_absence', 'teacher_absence')),
                absent_name TEXT NOT NULL,
                absent_civil_id TEXT,
                student_id INTEGER REFERENCES students(id) ON DELETE SET NULL,
                class_id INTEGER REFERENCES classes(id) ON DELETE SET NULL,
                department TEXT,
                submitted_by_civil_id TEXT NOT NULL,
                submitted_by_name TEXT NOT NULL,
                submitted_by_role TEXT NOT NULL,
                report_day TEXT NOT NULL,
                created_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'new' CHECK(status IN ('new', 'reviewed'))
            );

            CREATE UNIQUE INDEX IF NOT EXISTS idx_absent_student_once_per_day
                ON attendance_reports(school_id, report_day, class_id, absent_name)
                WHERE report_type = 'student_absence';
            CREATE UNIQUE INDEX IF NOT EXISTS idx_absent_teacher_once_per_day
                ON attendance_reports(school_id, report_day, department, absent_civil_id)
                WHERE report_type = 'teacher_absence';

            CREATE TABLE IF NOT EXISTS imported_legacy_data (
                school_id INTEGER PRIMARY KEY REFERENCES schools(id) ON DELETE CASCADE,
                imported_at TEXT NOT NULL
            );
            """
        )

        if _table_exists(connection, "school_accounts"):
            old_columns = _columns(connection, "school_accounts")
            if {"civil_id", "school_name", "password_hash"}.issubset(old_columns):
                accounts = connection.execute(
                    "SELECT civil_id, school_name, password_hash FROM school_accounts"
                ).fetchall()
                for account in accounts:
                    connection.execute(
                        """
                        INSERT OR IGNORE INTO schools (civil_id, school_name, password_hash, created_at)
                        VALUES (?, ?, ?, ?)
                        """,
                        (
                            account["civil_id"],
                            account["school_name"],
                            account["password_hash"],
                            _now().isoformat(timespec="seconds"),
                        ),
                    )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _now():
    return datetime.now(timezone(timedelta(hours=3)))


def _school_id():
    value = session.get("school_id")
    if value is None:
        raise ApiError("سجّلي الدخول أولاً.", 401)
    try:
        school_id = int(value)
    except (TypeError, ValueError):
        session.clear()
        raise ApiError("سجّلي الدخول أولاً.", 401)
    if get_db().execute("SELECT 1 FROM schools WHERE id = ?", (school_id,)).fetchone() is None:
        session.clear()
        raise ApiError("انتهت صلاحية جلسة المدرسة. سجّلي الدخول مجدداً.", 401)
    return school_id


def _identity():
    if "civil_id" not in session:
        raise ApiError("سجّلي الدخول أولاً.", 401)
    return {
        "civil_id": session["civil_id"],
        "name": session["name"],
        "role": session["role"],
        "department": session.get("department"),
    }


def _require_roles(*roles):
    def decorate(function):
        @wraps(function)
        def wrapped(*args, **kwargs):
            if session.get("role") not in roles:
                raise ApiError("ليس لديكِ صلاحية لتنفيذ هذا الإجراء.", 403)
            return function(*args, **kwargs)

        return wrapped

    return decorate


def _json_body():
    if not request.is_json:
        raise ApiError("صيغة الطلب غير صحيحة.")
    return request.get_json(silent=False) or {}


def _text(value, label, maximum=120):
    result = str(value or "").strip()
    if not result or len(result) > maximum:
        raise ApiError(f"تحققي من حقل {label}.")
    return result


def _school(school_id):
    school = get_db().execute(
        "SELECT id, civil_id, school_name FROM schools WHERE id = ?",
        (school_id,),
    ).fetchone()
    if school is None:
        raise ApiError("حساب المدرسة غير موجود.", 404)
    return school


def _import_legacy_records(school_id):
    connection = get_db()
    if connection.execute(
        "SELECT 1 FROM imported_legacy_data WHERE school_id = ?", (school_id,)
    ).fetchone():
        return
    if connection.execute("SELECT 1 FROM imported_legacy_data LIMIT 1").fetchone():
        connection.execute(
            "INSERT INTO imported_legacy_data (school_id, imported_at) VALUES (?, ?)",
            (school_id, _now().isoformat(timespec="seconds")),
        )
        return

    if _table_exists(connection, "legacy_students"):
        student_columns = _columns(connection, "legacy_students")
        if {"student_name", "grade", "section"}.issubset(student_columns):
            legacy_students = connection.execute(
                "SELECT student_name, grade, section FROM legacy_students"
            ).fetchall()
            for student in legacy_students:
                name = str(student["student_name"] or "").strip()
                grade = str(student["grade"] or "").strip()
                section = str(student["section"] or "").strip()
                if not name or not grade or not section:
                    continue
                cursor = connection.execute(
                    """
                    INSERT OR IGNORE INTO classes (school_id, grade_name, section_name, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (school_id, grade, section, _now().isoformat(timespec="seconds")),
                )
                class_row = connection.execute(
                    "SELECT id FROM classes WHERE school_id = ? AND grade_name = ? AND section_name = ?",
                    (school_id, grade, section),
                ).fetchone()
                if cursor.rowcount >= 0 and class_row:
                    connection.execute(
                        """
                        INSERT OR IGNORE INTO students (school_id, class_id, full_name, created_at)
                        VALUES (?, ?, ?, ?)
                        """,
                        (school_id, class_row["id"], name, _now().isoformat(timespec="seconds")),
                    )

    if _table_exists(connection, "legacy_teachers"):
        teacher_columns = _columns(connection, "legacy_teachers")
        if {"civil_id", "full_name", "department"}.issubset(teacher_columns):
            legacy_teachers = connection.execute(
                "SELECT civil_id, full_name, department FROM legacy_teachers"
            ).fetchall()
            for teacher in legacy_teachers:
                civil_id = normalize_civil_id(teacher["civil_id"])
                name = str(teacher["full_name"] or "").strip()
                department = str(teacher["department"] or "").strip()
                if civil_id and len(civil_id) <= 32 and name and department:
                    connection.execute(
                        """
                        INSERT OR IGNORE INTO teachers (school_id, civil_id, full_name, department)
                        VALUES (?, ?, ?, ?)
                        """,
                        (school_id, civil_id, name, department),
                    )

    connection.execute(
        "INSERT OR IGNORE INTO imported_legacy_data (school_id, imported_at) VALUES (?, ?)",
        (school_id, _now().isoformat(timespec="seconds")),
    )


def create_app(database_path=None):
    app = Flask(__name__, static_folder="static", template_folder="templates")
    app.config.update(
        DATABASE=str(database_path or DB_PATH),
        SECRET_KEY=os.environ.get("HADEER_SECRET_KEY") or secrets.token_hex(32),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=os.environ.get("HADEER_COOKIE_SECURE", "").lower() == "true",
        MAX_CONTENT_LENGTH=2 * 1024 * 1024,
    )
    Path(app.config["DATABASE"]).parent.mkdir(parents=True, exist_ok=True)
    initialize_database(app.config["DATABASE"])

    @app.teardown_appcontext
    def close_db(error=None):
        connection = g.pop("db", None)
        if connection is not None:
            connection.close()

    @app.after_request
    def finish_database_transaction(response):
        connection = g.get("db")
        if connection is not None:
            if response.status_code < 400:
                try:
                    connection.commit()
                except sqlite3.Error:
                    connection.rollback()
                    app.logger.exception("Could not commit database transaction")
                    return jsonify(error="تعذر حفظ البيانات في قاعدة البيانات."), 500
            else:
                connection.rollback()
        return response

    @app.errorhandler(ApiError)
    def handle_api_error(error):
        return jsonify(error=str(error)), error.status

    @app.errorhandler(sqlite3.IntegrityError)
    def handle_integrity_error(error):
        app.logger.warning("Database constraint rejected a request: %s", error)
        return jsonify(error="توجد بيانات مكررة أو مرتبطة بسجل غير صالح."), 409

    @app.errorhandler(sqlite3.Error)
    def handle_database_error(error):
        app.logger.exception("Database operation failed")
        return jsonify(error="تعذر حفظ البيانات في قاعدة البيانات."), 500

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/logo")
    def school_logo():
        return send_from_directory(LOGO_DIR, LOGO_NAME)

    @app.get("/manifest.webmanifest")
    def manifest():
        return app.send_static_file("manifest.webmanifest")

    @app.get("/sw.js")
    def service_worker():
        response = app.send_static_file("sw.js")
        response.headers["Service-Worker-Allowed"] = "/"
        response.headers["Cache-Control"] = "no-cache"
        return response

    @app.get("/api/config")
    def api_config():
        return jsonify(departments=DEPARTMENTS)

    @app.get("/api/session")
    def api_session():
        if "role" not in session:
            return jsonify(user=None)
        school_id = session.get("school_id")
        if school_id is None or get_db().execute(
            "SELECT 1 FROM schools WHERE id = ?", (school_id,)
        ).fetchone() is None:
            session.clear()
            return jsonify(user=None)
        return jsonify(
            user={
                "role": session["role"],
                "civil_id": session.get("civil_id"),
                "name": session.get("name"),
                "department": session.get("department"),
                "school_name": session.get("school_name"),
            }
        )

    @app.post("/api/auth/school/register")
    def register_school():
        data = _json_body()
        name = _text(data.get("school_name"), "اسم المدرسة")
        civil_id = normalize_civil_id(data.get("civil_id"))
        password = str(data.get("password") or "")
        if not valid_civil_id(civil_id):
            raise ApiError("يجب أن يتكون الرقم المدني من 12 رقماً.")
        if len(password) < 8 or len(password) > 256:
            raise ApiError("يجب أن تتكون كلمة المرور من 8 أحرف أو أرقام على الأقل.")

        connection = get_db()
        try:
            cursor = connection.execute(
                """
                INSERT INTO schools (civil_id, school_name, password_hash, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (civil_id, name, _password_hash(password), _now().isoformat(timespec="seconds")),
            )
        except sqlite3.IntegrityError:
            raise ApiError("يوجد حساب مسجل بهذا الرقم المدني بالفعل.", 409)
        school_id = cursor.lastrowid
        _import_legacy_records(school_id)
        session.clear()
        session.update(
            school_id=school_id,
            school_civil_id=civil_id,
            school_name=name,
            role="school",
            civil_id=civil_id,
            name=name,
        )
        return jsonify(ok=True), 201

    @app.post("/api/auth/school/login")
    def login_school():
        data = _json_body()
        civil_id = normalize_civil_id(data.get("civil_id"))
        password = str(data.get("password") or "")
        if not valid_civil_id(civil_id):
            raise ApiError("يجب أن يتكون الرقم المدني من 12 رقماً.")
        account = get_db().execute(
            "SELECT id, civil_id, school_name, password_hash FROM schools WHERE civil_id = ?",
            (civil_id,),
        ).fetchone()
        if account is None or not _password_matches(password, account["password_hash"]):
            raise ApiError("بيانات المدرسة غير صحيحة أو لم يتم تسجيلها.", 401)
        session.clear()
        session.update(
            school_id=account["id"],
            school_civil_id=account["civil_id"],
            school_name=account["school_name"],
            role="school",
            civil_id=account["civil_id"],
            name=account["school_name"],
        )
        _import_legacy_records(account["id"])
        return jsonify(ok=True)

    @app.post("/api/auth/staff/login")
    def login_staff():
        data = _json_body()
        name = _text(data.get("full_name"), "الاسم الكامل")
        civil_id = normalize_civil_id(data.get("civil_id"))
        role = data.get("role")
        department = _text(data.get("department"), "القسم")
        if role not in ("teacher", "department_head"):
            raise ApiError("نوع الحساب غير صحيح.")
        if not valid_civil_id(civil_id):
            raise ApiError("يجب أن يتكون الرقم المدني من 12 رقماً.")
        school_id = data.get("school_id")
        if school_id is None:
            raise ApiError("اختاري المدرسة أولاً.")
        try:
            school_id = int(school_id)
        except (ValueError, TypeError):
            raise ApiError("المدرسة المختارة غير صحيحة.")
        teacher = get_db().execute(
            """
            SELECT civil_id, full_name, department, is_department_head
            FROM teachers
            WHERE school_id = ? AND civil_id = ? AND full_name = ? AND department = ?
            """,
            (school_id, civil_id, name, department),
        ).fetchone()
        is_head = bool(teacher["is_department_head"]) if teacher else False
        if teacher is None or (role == "department_head" and not is_head):
            raise ApiError("البيانات غير مطابقة لسجل المدرسة أو لا تملكين هذه الصلاحية.", 401)
        school = _school(school_id)
        session.clear()
        session.update(
            school_id=school_id,
            school_civil_id=school["civil_id"],
            school_name=school["school_name"],
            role=role,
            civil_id=civil_id,
            name=name,
            department=department,
        )
        return jsonify(ok=True)

    @app.post("/api/auth/logout")
    def logout():
        session.clear()
        return jsonify(ok=True)

    @app.get("/api/schools")
    def list_schools():
        rows = get_db().execute("SELECT id, school_name FROM schools ORDER BY school_name").fetchall()
        return jsonify(schools=[dict(row) for row in rows])

    @app.get("/api/admin/overview")
    @_require_roles("school")
    def admin_overview():
        school_id = _school_id()
        connection = get_db()
        new_reports = connection.execute(
            "SELECT COUNT(*) FROM attendance_reports WHERE school_id = ? AND status = 'new'",
            (school_id,),
        ).fetchone()[0]
        return jsonify(
            school_name=session["school_name"],
            classes=connection.execute(
                "SELECT COUNT(*) FROM classes WHERE school_id = ?", (school_id,)
            ).fetchone()[0],
            teachers=connection.execute(
                "SELECT COUNT(*) FROM teachers WHERE school_id = ?", (school_id,)
            ).fetchone()[0],
            students=connection.execute(
                "SELECT COUNT(*) FROM students WHERE school_id = ?", (school_id,)
            ).fetchone()[0],
            new_reports=new_reports,
        )

    @app.get("/api/admin/classes")
    @_require_roles("school")
    def admin_classes():
        rows = get_db().execute(
            """
            SELECT c.id, c.grade_name, c.section_name, COUNT(DISTINCT s.id) AS student_count
            FROM classes c LEFT JOIN students s ON s.class_id = c.id
            WHERE c.school_id = ?
            GROUP BY c.id ORDER BY c.grade_name, c.section_name
            """,
            (_school_id(),),
        ).fetchall()
        return jsonify(classes=[dict(row) for row in rows])

    @app.post("/api/admin/classes")
    @_require_roles("school")
    def create_class():
        data = _json_body()
        school_id = _school_id()
        grade = _text(data.get("grade_name"), "الصف", 80)
        section = _text(data.get("section_name"), "الشعبة", 80)
        cursor = get_db().execute(
            """
            INSERT INTO classes (school_id, grade_name, section_name, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (school_id, grade, section, _now().isoformat(timespec="seconds")),
        )
        return jsonify(id=cursor.lastrowid, grade_name=grade, section_name=section), 201

    @app.get("/api/admin/teachers")
    @_require_roles("school")
    def admin_teachers():
        school_id = _school_id()
        rows = get_db().execute(
            """
            SELECT t.civil_id, t.full_name, t.department, t.is_department_head,
                   GROUP_CONCAT(tc.class_id) AS class_ids,
                   GROUP_CONCAT(c.grade_name || ' / ' || c.section_name, '، ') AS class_names
            FROM teachers t
            LEFT JOIN teacher_classes tc
                ON tc.school_id = t.school_id AND tc.teacher_civil_id = t.civil_id
            LEFT JOIN classes c ON c.id = tc.class_id
            WHERE t.school_id = ?
            GROUP BY t.school_id, t.civil_id
            ORDER BY t.department, t.full_name
            """,
            (school_id,),
        ).fetchall()
        teachers = []
        for row in rows:
            teacher = dict(row)
            teacher["is_department_head"] = bool(teacher["is_department_head"])
            teacher["class_ids"] = [int(value) for value in (teacher["class_ids"] or "").split(",") if value]
            teachers.append(teacher)
        return jsonify(teachers=teachers, departments=DEPARTMENTS)

    @app.post("/api/admin/teachers")
    @_require_roles("school")
    def save_teacher():
        data = _json_body()
        school_id = _school_id()
        civil_id = normalize_civil_id(data.get("civil_id"))
        name = _text(data.get("full_name"), "الاسم الكامل")
        department = _text(data.get("department"), "القسم")
        class_ids = data.get("class_ids") or []
        is_head = bool(data.get("is_department_head"))
        if not valid_civil_id(civil_id):
            raise ApiError("يجب أن يتكون الرقم المدني للمعلمة من 12 رقماً.")
        if department not in DEPARTMENTS:
            raise ApiError("اختاري قسماً من القائمة.")
        if not isinstance(class_ids, list) or len(class_ids) > 100:
            raise ApiError("قائمة الصفوف غير صحيحة.")
        try:
            class_ids = sorted({int(value) for value in class_ids})
        except (ValueError, TypeError):
            raise ApiError("تحتوي قائمة الصفوف على اختيار غير صحيح.")
        original_civil_id = normalize_civil_id(data.get("original_civil_id") or civil_id)
        if class_ids:
            placeholders = ",".join("?" for _ in class_ids)
            count = get_db().execute(
                f"SELECT COUNT(*) FROM classes WHERE school_id = ? AND id IN ({placeholders})",
                [school_id, *class_ids],
            ).fetchone()[0]
            if count != len(class_ids):
                raise ApiError("اختاري صفوفاً تابعة لهذه المدرسة فقط.", 403)

        connection = get_db()
        if original_civil_id != civil_id:
            existing = connection.execute(
                "SELECT 1 FROM teachers WHERE school_id = ? AND civil_id = ?",
                (school_id, original_civil_id),
            ).fetchone()
            if existing is None:
                raise ApiError("لم يتم العثور على سجل المعلمة المراد تعديله.", 404)
            connection.execute(
                "DELETE FROM teachers WHERE school_id = ? AND civil_id = ?",
                (school_id, original_civil_id),
            )
        connection.execute(
            """
            INSERT INTO teachers (school_id, civil_id, full_name, department, is_department_head)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(school_id, civil_id) DO UPDATE SET
                full_name = excluded.full_name,
                department = excluded.department,
                is_department_head = excluded.is_department_head
            """,
            (school_id, civil_id, name, department, int(is_head)),
        )
        connection.execute(
            "DELETE FROM teacher_classes WHERE school_id = ? AND teacher_civil_id = ?",
            (school_id, civil_id),
        )
        connection.executemany(
            """
            INSERT INTO teacher_classes (school_id, teacher_civil_id, class_id)
            VALUES (?, ?, ?)
            """,
            [(school_id, civil_id, class_id) for class_id in class_ids],
        )
        return jsonify(ok=True), 201

    @app.get("/api/admin/students")
    @_require_roles("school")
    def admin_students():
        school_id = _school_id()
        try:
            class_id = int(request.args.get("class_id", ""))
        except ValueError:
            raise ApiError("اختاري الصف والشعبة أولاً.")
        rows = get_db().execute(
            """
            SELECT id, full_name FROM students
            WHERE school_id = ? AND class_id = ? ORDER BY full_name
            """,
            (school_id, class_id),
        ).fetchall()
        return jsonify(students=[dict(row) for row in rows])

    @app.post("/api/admin/students")
    @_require_roles("school")
    def add_students():
        data = _json_body()
        school_id = _school_id()
        try:
            class_id = int(data.get("class_id"))
        except (ValueError, TypeError):
            raise ApiError("اختاري الصف والشعبة أولاً.")
        names = data.get("names")
        if not isinstance(names, list):
            raise ApiError("أدخلي أسماء الطالبات.")
        names = list(dict.fromkeys(str(name).strip() for name in names if str(name).strip()))
        if not names or len(names) > 500 or any(len(name) > 120 for name in names):
            raise ApiError("أدخلي من اسماً واحداً إلى 500 اسم، على ألا يتجاوز الاسم 120 حرفاً.")
        class_row = get_db().execute(
            "SELECT id FROM classes WHERE id = ? AND school_id = ?", (class_id, school_id)
        ).fetchone()
        if class_row is None:
            raise ApiError("هذا الصف لا يتبع حساب المدرسة.", 403)
        connection = get_db()
        before = connection.total_changes
        connection.executemany(
            """
            INSERT OR IGNORE INTO students (school_id, class_id, full_name, created_at)
            VALUES (?, ?, ?, ?)
            """,
            [(school_id, class_id, name, _now().isoformat(timespec="seconds")) for name in names],
        )
        return jsonify(added=connection.total_changes - before), 201

    @app.delete("/api/admin/students/<int:student_id>")
    @_require_roles("school")
    def remove_student(student_id):
        cursor = get_db().execute(
            "DELETE FROM students WHERE id = ? AND school_id = ?",
            (student_id, _school_id()),
        )
        if not cursor.rowcount:
            raise ApiError("لم يتم العثور على الطالبة.", 404)
        return jsonify(ok=True)

    @app.get("/api/teacher/classes")
    @_require_roles("teacher")
    def teacher_classes():
        rows = get_db().execute(
            """
            SELECT c.id, c.grade_name, c.section_name, COUNT(s.id) AS student_count
            FROM teacher_classes tc
            JOIN classes c ON c.id = tc.class_id AND c.school_id = tc.school_id
            LEFT JOIN students s ON s.class_id = c.id AND s.school_id = c.school_id
            WHERE tc.school_id = ? AND tc.teacher_civil_id = ?
            GROUP BY c.id ORDER BY c.grade_name, c.section_name
            """,
            (_school_id(), session["civil_id"]),
        ).fetchall()
        return jsonify(classes=[dict(row) for row in rows])

    @app.get("/api/teacher/classes/<int:class_id>/students")
    @_require_roles("teacher")
    def teacher_students(class_id):
        school_id = _school_id()
        assigned = get_db().execute(
            """
            SELECT 1 FROM teacher_classes
            WHERE school_id = ? AND teacher_civil_id = ? AND class_id = ?
            """,
            (school_id, session["civil_id"], class_id),
        ).fetchone()
        if assigned is None:
            raise ApiError("هذا الصف غير مدرج ضمن صفوفكِ.", 403)
        rows = get_db().execute(
            "SELECT id, full_name FROM students WHERE school_id = ? AND class_id = ? ORDER BY full_name",
            (school_id, class_id),
        ).fetchall()
        return jsonify(students=[dict(row) for row in rows])

    @app.get("/api/head/classes")
    @_require_roles("department_head")
    def head_classes():
        rows = get_db().execute(
            """
            SELECT c.id, c.grade_name, c.section_name, COUNT(s.id) AS student_count
            FROM teacher_classes tc
            JOIN classes c ON c.id = tc.class_id AND c.school_id = tc.school_id
            LEFT JOIN students s ON s.class_id = c.id AND s.school_id = c.school_id
            WHERE tc.school_id = ? AND tc.teacher_civil_id = ?
            GROUP BY c.id ORDER BY c.grade_name, c.section_name
            """,
            (_school_id(), session["civil_id"]),
        ).fetchall()
        return jsonify(classes=[dict(row) for row in rows])

    @app.get("/api/head/classes/<int:class_id>/students")
    @_require_roles("department_head")
    def head_students(class_id):
        school_id = _school_id()
        assigned = get_db().execute(
            """
            SELECT 1 FROM teacher_classes
            WHERE school_id = ? AND teacher_civil_id = ? AND class_id = ?
            """,
            (school_id, session["civil_id"], class_id),
        ).fetchone()
        if assigned is None:
            raise ApiError("هذا الصف غير مدرج ضمن صفوفكِ.", 403)
        rows = get_db().execute(
            "SELECT id, full_name FROM students WHERE school_id = ? AND class_id = ? ORDER BY full_name",
            (school_id, class_id),
        ).fetchall()
        return jsonify(students=[dict(row) for row in rows])

    @app.post("/api/teacher/absence")
    @app.post("/api/head/student-absence")
    @_require_roles("teacher", "department_head")
    def report_student_absence():
        data = _json_body()
        school_id = _school_id()
        try:
            class_id = int(data.get("class_id"))
        except (ValueError, TypeError):
            raise ApiError("اختاري الصف أولاً.")
        assigned = get_db().execute(
            """
            SELECT 1 FROM teacher_classes
            WHERE school_id = ? AND teacher_civil_id = ? AND class_id = ?
            """,
            (school_id, session["civil_id"], class_id),
        ).fetchone()
        if assigned is None:
            raise ApiError("هذا الصف غير مدرج ضمن صفوفكِ.", 403)

        student_ids = data.get("student_ids") or []
        manual_names = data.get("manual_names") or []
        if not isinstance(student_ids, list) or not isinstance(manual_names, list):
            raise ApiError("قائمة الغياب غير صحيحة.")
        if len(student_ids) + len(manual_names) > 200:
            raise ApiError("لا يمكن تسجيل أكثر من 200 اسم في عملية الغياب الواحدة.")
        try:
            student_ids = sorted({int(value) for value in student_ids})
        except (ValueError, TypeError):
            raise ApiError("اختيار الطالبات يحتوي على بيانات غير صحيحة.")
        manual_names = list(dict.fromkeys(str(name).strip() for name in manual_names if str(name).strip()))
        if any(len(name) > 120 for name in manual_names):
            raise ApiError("يجب ألا يتجاوز اسم الطالبة 120 حرفاً.")
        if not student_ids and not manual_names:
            raise ApiError("اختاري طالبة غائبة أو اكتبي اسمها.")

        connection = get_db()
        if student_ids:
            placeholders = ",".join("?" for _ in student_ids)
            valid_count = connection.execute(
                f"SELECT COUNT(*) FROM students WHERE school_id = ? AND class_id = ? AND id IN ({placeholders})",
                [school_id, class_id, *student_ids],
            ).fetchone()[0]
            if valid_count != len(student_ids):
                raise ApiError("تحتوي القائمة على طالبة من صف آخر.", 403)
        class_row = connection.execute(
            "SELECT grade_name, section_name FROM classes WHERE id = ? AND school_id = ?",
            (class_id, school_id),
        ).fetchone()
        now = _now()
        report_day = now.date().isoformat()
        timestamp = now.isoformat(timespec="seconds")
        report_names = []
        for student_id in student_ids:
            student = connection.execute(
                "SELECT full_name FROM students WHERE id = ?", (student_id,)
            ).fetchone()
            report_names.append((student["full_name"], student_id))
        for name in manual_names:
            existing = connection.execute(
                """
                SELECT id FROM students WHERE school_id = ? AND class_id = ? AND full_name = ?
                """,
                (school_id, class_id, name),
            ).fetchone()
            report_names.append((name, existing["id"] if existing else None))

        added = 0
        for name, student_id in report_names:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO attendance_reports
                    (school_id, report_type, absent_name, student_id, class_id,
                     submitted_by_civil_id, submitted_by_name, submitted_by_role,
                     report_day, created_at)
                VALUES (?, 'student_absence', ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    school_id,
                    name,
                    student_id,
                    class_id,
                    session["civil_id"],
                    session["name"],
                    session["role"],
                    report_day,
                    timestamp,
                ),
            )
            added += cursor.rowcount
        return jsonify(
            added=added,
            duplicates=len(report_names) - added,
            class_name=f"{class_row['grade_name']} / {class_row['section_name']}",
        ), 201

    @app.get("/api/head/teachers")
    @_require_roles("department_head")
    def department_teachers():
        rows = get_db().execute(
            """
            SELECT civil_id, full_name FROM teachers
            WHERE school_id = ? AND department = ? AND civil_id != ?
            ORDER BY full_name
            """,
            (_school_id(), session["department"], session["civil_id"]),
        ).fetchall()
        return jsonify(teachers=[dict(row) for row in rows])

    @app.post("/api/head/absence")
    @_require_roles("department_head")
    def report_teacher_absence():
        data = _json_body()
        civil_ids = data.get("teacher_civil_ids") or []
        if not isinstance(civil_ids, list) or not civil_ids or len(civil_ids) > 100:
            raise ApiError("اختاري معلمة غائبة واحدة على الأقل.")
        civil_ids = list(dict.fromkeys(normalize_civil_id(value) for value in civil_ids))
        school_id = _school_id()
        placeholders = ",".join("?" for _ in civil_ids)
        rows = get_db().execute(
            f"""
            SELECT civil_id, full_name FROM teachers
            WHERE school_id = ? AND department = ? AND civil_id IN ({placeholders})
            """,
            [school_id, session["department"], *civil_ids],
        ).fetchall()
        if len(rows) != len(civil_ids):
            raise ApiError("اختاري معلمات من قسمكِ فقط.", 403)
        now = _now()
        added = 0
        for teacher in rows:
            cursor = get_db().execute(
                """
                INSERT OR IGNORE INTO attendance_reports
                    (school_id, report_type, absent_name, absent_civil_id, department,
                     submitted_by_civil_id, submitted_by_name, submitted_by_role,
                     report_day, created_at)
                VALUES (?, 'teacher_absence', ?, ?, ?, ?, ?, 'department_head', ?, ?)
                """,
                (
                    school_id,
                    teacher["full_name"],
                    teacher["civil_id"],
                    session["department"],
                    session["civil_id"],
                    session["name"],
                    now.date().isoformat(),
                    now.isoformat(timespec="seconds"),
                ),
            )
            added += cursor.rowcount
        return jsonify(added=added, duplicates=len(rows) - added), 201

    @app.get("/api/admin/reports")
    @_require_roles("school")
    def admin_reports():
        report_type = request.args.get("type", "")
        query = """
            SELECT r.id, r.report_type, r.absent_name, r.absent_civil_id, r.department,
                   r.submitted_by_name, r.submitted_by_role, r.report_day, r.created_at,
                   r.status, c.grade_name, c.section_name
            FROM attendance_reports r
            LEFT JOIN classes c ON c.id = r.class_id
            WHERE r.school_id = ?
        """
        params = [_school_id()]
        if report_type in ("student_absence", "teacher_absence"):
            query += " AND r.report_type = ?"
            params.append(report_type)
        query += " ORDER BY r.created_at DESC, r.id DESC LIMIT 500"
        rows = get_db().execute(query, params).fetchall()
        return jsonify(reports=[dict(row) for row in rows])

    @app.post("/api/admin/reports/<int:report_id>/review")
    @_require_roles("school")
    def review_report(report_id):
        cursor = get_db().execute(
            "UPDATE attendance_reports SET status = 'reviewed' WHERE id = ? AND school_id = ?",
            (report_id, _school_id()),
        )
        if not cursor.rowcount:
            raise ApiError("لم يتم العثور على سجل الغياب.", 404)
        return jsonify(ok=True)

    return app


app = create_app()


if __name__ == "__main__":
    app.run(
        host=os.environ.get("HADEER_HOST", "0.0.0.0"),
        port=int(os.environ.get("PORT", "5000")),
        debug=False,
    )
