"""
Сайт кафедры «Программное Обеспечение Компьютерных Систем»
Кыргызского Государственного Технического Университета им. И. Раззакова
"""

from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import os

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "kgtu-poks-secret-2024")

# ── Данные кафедры ────────────────────────────────────────────────────────────
DEPARTMENT = {
    "name":       "Программное Обеспечение Компьютерных Систем",
    "short":      "ПОКС",
    "university": "Кыргызский Государственный Технический Университет им. И. Раззакова",
    "faculty":    "Институт Информационных Технологий",
    "address":    "г. Бишкек, пр. Мира 66",
    "email":      "poks@kgtu.kg",
    "phone":      "+996 (312) 54-51-72",
    "founded":    "1995",
}

TEACHERS = [
    {
        "id":       1,
        "name":     "ФАМИЛИЯ ИМЯ ОТЧЕСТВО",
        "position": "Заведующий кафедрой, д.т.н., профессор",
        "subjects": ["Алгоритмы и структуры данных", "Программная инженерия"],
        "email":    "head@kgtu.kg",
        "office":   "Каб. 301",
        "bio":      "Заведующий кафедрой ПОКС. Специализируется в области системного программирования и алгоритмов.",
        "initials": "ФИ",
    },
    {
        "id":       2,
        "name":     "ФАМИЛИЯ ИМЯ ОТЧЕСТВО",
        "position": "Доцент, к.т.н.",
        "subjects": ["Базы данных", "Web-разработка", "Python"],
        "email":    "teacher2@kgtu.kg",
        "office":   "Каб. 302",
        "bio":      "Специализируется в области баз данных и веб-технологий. Ведёт практические занятия по Python.",
        "initials": "ФИ",
    },
    {
        "id":       3,
        "name":     "ФАМИЛИЯ ИМЯ ОТЧЕСТВО",
        "position": "Старший преподаватель",
        "subjects": ["Информационная безопасность", "Сетевые технологии"],
        "email":    "teacher3@kgtu.kg",
        "office":   "Каб. 303",
        "bio":      "Специалист в области информационной безопасности и сетевых технологий.",
        "initials": "ФИ",
    },
    {
        "id":       4,
        "name":     "ФАМИЛИЯ ИМЯ ОТЧЕСТВО",
        "position": "Преподаватель",
        "subjects": ["Операционные системы", "Linux", "Docker"],
        "email":    "teacher4@kgtu.kg",
        "office":   "Каб. 304",
        "bio":      "Ведёт курсы по операционным системам и современным технологиям контейнеризации.",
        "initials": "ФИ",
    },
    {
        "id":       5,
        "name":     "ФАМИЛИЯ ИМЯ ОТЧЕСТВО",
        "position": "Ассистент",
        "subjects": ["Программирование на C++", "Объектно-ориентированное программирование"],
        "email":    "teacher5@kgtu.kg",
        "office":   "Каб. 305",
        "bio":      "Молодой специалист, ведёт занятия по программированию на C++ и ООП.",
        "initials": "ФИ",
    },
]

DISCIPLINES = [
    {"name": "Алгоритмы и структуры данных",         "semester": "1-2", "credits": 5, "type": "Обязательная"},
    {"name": "Объектно-ориентированное программирование", "semester": "2", "credits": 4, "type": "Обязательная"},
    {"name": "Базы данных",                           "semester": "3",   "credits": 5, "type": "Обязательная"},
    {"name": "Операционные системы",                  "semester": "3",   "credits": 4, "type": "Обязательная"},
    {"name": "Сетевые технологии",                    "semester": "4",   "credits": 4, "type": "Обязательная"},
    {"name": "Информационная безопасность",           "semester": "4",   "credits": 4, "type": "Обязательная"},
    {"name": "Web-разработка",                        "semester": "5",   "credits": 5, "type": "Обязательная"},
    {"name": "Программная инженерия",                 "semester": "5",   "credits": 4, "type": "Обязательная"},
    {"name": "Машинное обучение",                     "semester": "6",   "credits": 5, "type": "По выбору"},
    {"name": "Мобильная разработка",                  "semester": "6",   "credits": 4, "type": "По выбору"},
    {"name": "DevOps и контейнеризация",              "semester": "7",   "credits": 4, "type": "По выбору"},
    {"name": "Дипломная работа",                      "semester": "8",   "credits": 12,"type": "Обязательная"},
]

NEWS = [
    {
        "id":    1,
        "title": "Открытие нового компьютерного класса",
        "date":  "15 мая 2026",
        "text":  "На кафедре ПОКС открылся новый компьютерный класс, оснащённый современным оборудованием для практических занятий по программированию и сетевым технологиям.",
        "tag":   "Инфраструктура",
    },
    {
        "id":    2,
        "title": "Студенты кафедры заняли 2 место на республиканской олимпиаде",
        "date":  "28 апреля 2026",
        "text":  "Команда студентов кафедры ПОКС заняла второе место на республиканской олимпиаде по программированию среди технических университетов Кыргызстана.",
        "tag":   "Достижения",
    },
    {
        "id":    3,
        "title": "Приглашение на день открытых дверей",
        "date":  "10 апреля 2026",
        "text":  "Кафедра ПОКС приглашает абитуриентов и их родителей на день открытых дверей. Вы сможете познакомиться с преподавателями, посетить лаборатории и узнать о программах обучения.",
        "tag":   "Мероприятия",
    },
    {
        "id":    4,
        "title": "Новый курс по кибербезопасности",
        "date":  "1 марта 2026",
        "text":  "С весеннего семестра на кафедре введён новый курс по кибербезопасности и защите информационных систем. Курс включает практические лабораторные работы.",
        "tag":   "Учебный процесс",
    },
]

SCHEDULE = {
    "Понедельник": [
        {"time": "08:00–09:30", "subject": "Алгоритмы и структуры данных",    "group": "ПО-21",  "room": "Каб. 201", "teacher": "ФАМИЛИЯ И.О."},
        {"time": "09:45–11:15", "subject": "Базы данных",                     "group": "ПО-22",  "room": "Каб. 302", "teacher": "ФАМИЛИЯ И.О."},
        {"time": "11:30–13:00", "subject": "Информационная безопасность",      "group": "ПО-41",  "room": "Каб. 105", "teacher": "ФАМИЛИЯ И.О."},
        {"time": "14:00–15:30", "subject": "Web-разработка",                   "group": "ПО-31",  "room": "Каб. 302", "teacher": "ФАМИЛИЯ И.О."},
    ],
    "Вторник": [
        {"time": "08:00–09:30", "subject": "Операционные системы",             "group": "ПО-22",  "room": "Каб. 201", "teacher": "ФАМИЛИЯ И.О."},
        {"time": "09:45–11:15", "subject": "ООП",                              "group": "ПО-21",  "room": "Каб. 302", "teacher": "ФАМИЛИЯ И.О."},
        {"time": "11:30–13:00", "subject": "Сетевые технологии",               "group": "ПО-32",  "room": "Каб. 201", "teacher": "ФАМИЛИЯ И.О."},
        {"time": "14:00–15:30", "subject": "Программная инженерия",            "group": "ПО-41",  "room": "Каб. 301", "teacher": "ФАМИЛИЯ И.О."},
    ],
    "Среда": [
        {"time": "08:00–09:30", "subject": "Машинное обучение",                "group": "ПО-41",  "room": "Каб. 302", "teacher": "ФАМИЛИЯ И.О."},
        {"time": "09:45–11:15", "subject": "Алгоритмы и структуры данных",    "group": "ПО-22",  "room": "Каб. 201", "teacher": "ФАМИЛИЯ И.О."},
        {"time": "11:30–13:00", "subject": "DevOps и контейнеризация",         "group": "ПО-42",  "room": "Каб. 302", "teacher": "ФАМИЛИЯ И.О."},
    ],
    "Четверг": [
        {"time": "08:00–09:30", "subject": "Базы данных",                     "group": "ПО-21",  "room": "Каб. 302", "teacher": "ФАМИЛИЯ И.О."},
        {"time": "09:45–11:15", "subject": "Информационная безопасность",      "group": "ПО-42",  "room": "Каб. 105", "teacher": "ФАМИЛИЯ И.О."},
        {"time": "11:30–13:00", "subject": "Web-разработка",                   "group": "ПО-32",  "room": "Каб. 302", "teacher": "ФАМИЛИЯ И.О."},
        {"time": "14:00–15:30", "subject": "Мобильная разработка",             "group": "ПО-41",  "room": "Каб. 302", "teacher": "ФАМИЛИЯ И.О."},
    ],
    "Пятница": [
        {"time": "08:00–09:30", "subject": "ООП",                              "group": "ПО-22",  "room": "Каб. 302", "teacher": "ФАМИЛИЯ И.О."},
        {"time": "09:45–11:15", "subject": "Операционные системы",             "group": "ПО-21",  "room": "Каб. 201", "teacher": "ФАМИЛИЯ И.О."},
        {"time": "11:30–13:00", "subject": "Программная инженерия",            "group": "ПО-31",  "room": "Каб. 301", "teacher": "ФАМИЛИЯ И.О."},
    ],
}

# ── Тестовые пользователи ─────────────────────────────────────────────────────
USERS = {
    "student": {"password": "student123", "name": "Студент", "role": "student"},
    "admin":   {"password": "admin123",   "name": "Администратор", "role": "admin"},
}

# ── Маршруты ──────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html",
        dept=DEPARTMENT, news=NEWS[:3], teachers=TEACHERS[:4])


@app.route("/about")
def about():
    return render_template("about.html", dept=DEPARTMENT)


@app.route("/teachers")
def teachers():
    return render_template("teachers.html", dept=DEPARTMENT, teachers=TEACHERS)


@app.route("/teacher/<int:tid>")
def teacher(tid):
    t = next((t for t in TEACHERS if t["id"] == tid), None)
    if not t:
        return redirect(url_for("teachers"))
    return render_template("teacher.html", dept=DEPARTMENT, teacher=t)


@app.route("/disciplines")
def disciplines():
    return render_template("disciplines.html", dept=DEPARTMENT, disciplines=DISCIPLINES)


@app.route("/news")
def news():
    return render_template("news.html", dept=DEPARTMENT, news=NEWS)


@app.route("/schedule")
def schedule():
    return render_template("schedule.html", dept=DEPARTMENT, schedule=SCHEDULE)


@app.route("/contacts")
def contacts():
    return render_template("contacts.html", dept=DEPARTMENT)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        user = USERS.get(username)
        if user and user["password"] == password:
            session["user"]     = username
            session["name"]     = user["name"]
            session["role"]     = user["role"]
            return redirect(url_for("cabinet"))
        error = "Неверный логин или пароль"
    return render_template("login.html", dept=DEPARTMENT, error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/cabinet")
def cabinet():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("cabinet.html", dept=DEPARTMENT,
        name=session["name"], role=session["role"])


@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "КГТУ ПОКС Website"})


@app.route("/search")
def search():
    q = request.args.get("q", "")
    return jsonify({"query": q, "results": []})


@app.route("/comment", methods=["POST"])
def comment():
    data = request.get_json(silent=True) or {}
    return jsonify({"status": "ok", "comment": data.get("text", "")})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
