"""
Сайт кафедры «Программное Обеспечение Компьютерных Систем»
Кыргызского Государственного Технического Университета им. И. Раззакова
"""

from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import os

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "kgtu-poks-secret-2024")

DEPARTMENT = {
    "name":       "Программное Обеспечение Компьютерных Систем",
    "short":      "ПОКС",
    "university": "Кыргызский Государственный Технический Университет им. И. Раззакова",
    "faculty":    "Институт Информационных Технологий",
    "address":    "г. Бишкек, пр. Ч. Айтматова, 66",
    "email":      "poks@kgtu.kg",
    "phone":      "+996 (312) 54-51-72",
    "founded":    "1995",
}

TEACHERS = [
    {
        "id":       1,
        "name":     "Салиев Алишер Борубаевич",
        "position": "Заведующий кафедрой, д.ф.-м.н., профессор",
        "subjects": ["Высшая математика", "Математическое моделирование", "Численные методы"],
        "email":    "saliev@kgtu.kg",
        "office":   "Каб. 301",
        "bio":      "Заведующий кафедрой ПОКС. Доктор физико-математических наук, профессор. Специализируется в области математического моделирования и вычислительной математики.",
        "initials": "СА",
    },
    {
        "id":       2,
        "name":     "Тен Иосиф Григорьевич",
        "position": "к.т.н., профессор кафедры ПОКС",
        "subjects": ["Программная инженерия", "Проектирование ПО", "Паттерны проектирования"],
        "email":    "ten@kgtu.kg",
        "office":   "Каб. 302",
        "bio":      "Кандидат технических наук, профессор кафедры ПОКС. Имеет большой опыт в области разработки программного обеспечения и программной инженерии.",
        "initials": "ТИ",
    },
    {
        "id":       3,
        "name":     "Цой Ман-Су",
        "position": "к.т.н., профессор кафедры ПОКС",
        "subjects": ["Базы данных", "Информационные системы", "SQL"],
        "email":    "tsoi@kgtu.kg",
        "office":   "Каб. 303",
        "bio":      "Кандидат технических наук, профессор кафедры ПОКС. Специализируется в области баз данных и информационных систем.",
        "initials": "ЦМ",
    },
    {
        "id":       4,
        "name":     "Мусина Индира Рафиковна",
        "position": "к.т.н., доцент кафедры ПОКС",
        "subjects": ["Объектно-ориентированное программирование", "Java", "Python"],
        "email":    "musina@kgtu.kg",
        "office":   "Каб. 304",
        "bio":      "Кандидат технических наук, доцент кафедры ПОКС. Ведёт курсы по объектно-ориентированному программированию и современным языкам программирования.",
        "initials": "МИ",
    },
    {
        "id":       5,
        "name":     "Валеева Асия Асхатовна",
        "position": "к.ф.-м.н., доцент кафедры ПОКС",
        "subjects": ["Дискретная математика", "Теория алгоритмов", "Логика"],
        "email":    "valeeva@kgtu.kg",
        "office":   "Каб. 305",
        "bio":      "Кандидат физико-математических наук, доцент кафедры ПОКС. Специализируется в области дискретной математики и теории алгоритмов.",
        "initials": "ВА",
    },
    {
        "id":       6,
        "name":     "Искаков Рысбек Таабалдиевич",
        "position": "к.т.н., доцент кафедры ПОКС",
        "subjects": ["Сетевые технологии", "Компьютерные сети", "TCP/IP"],
        "email":    "iskakov@kgtu.kg",
        "office":   "Каб. 306",
        "bio":      "Кандидат технических наук, доцент кафедры ПОКС. Специализируется в области сетевых технологий и телекоммуникаций.",
        "initials": "ИР",
    },
    {
        "id":       7,
        "name":     "Стамкулова Гулдана Кубанычбековна",
        "position": "Доцент кафедры ПОКС",
        "subjects": ["Web-разработка", "HTML/CSS", "JavaScript", "PHP"],
        "email":    "stamkulova@kgtu.kg",
        "office":   "Каб. 307",
        "bio":      "Доцент кафедры ПОКС. Ведёт курсы по web-разработке и современным веб-технологиям.",
        "initials": "СГ",
    },
    {
        "id":       8,
        "name":     "Макиева Замира Джумакматовна",
        "position": "Доцент кафедры ПОКС",
        "subjects": ["Информационная безопасность", "Криптография", "Защита данных"],
        "email":    "makieva@kgtu.kg",
        "office":   "Каб. 308",
        "bio":      "Доцент кафедры ПОКС. Специализируется в области информационной безопасности и криптографии.",
        "initials": "МЗ",
    },
    {
        "id":       9,
        "name":     "Жогаштиев Нурлан Тилекович",
        "position": "Доцент кафедры ПОКС",
        "subjects": ["Операционные системы", "Linux", "Системное программирование"],
        "email":    "zhogashtiev@kgtu.kg",
        "office":   "Каб. 309",
        "bio":      "Доцент кафедры ПОКС. Ведёт курсы по операционным системам и системному программированию.",
        "initials": "ЖН",
    },
    {
        "id":       10,
        "name":     "Каткова Светлана Николаевна",
        "position": "Старший преподаватель кафедры ПОКС",
        "subjects": ["Программирование на C/C++", "Алгоритмы", "Структуры данных"],
        "email":    "katkova@kgtu.kg",
        "office":   "Каб. 310",
        "bio":      "Старший преподаватель кафедры ПОКС. Ведёт курсы по программированию на C/C++ и алгоритмам.",
        "initials": "КС",
    },
    {
        "id":       11,
        "name":     "Садралиева Рахат Аскарбековна",
        "position": "Старший преподаватель кафедры ПОКС",
        "subjects": ["Базы данных", "PostgreSQL", "MongoDB"],
        "email":    "sadralieva@kgtu.kg",
        "office":   "Каб. 311",
        "bio":      "Старший преподаватель кафедры ПОКС. Специализируется в области реляционных и NoSQL баз данных.",
        "initials": "СР",
    },
    {
        "id":       12,
        "name":     "Сабаева Кундуз Кубанычбековна",
        "position": "Старший преподаватель кафедры ПОКС",
        "subjects": ["Машинное обучение", "Data Science", "Python"],
        "email":    "sabaeva@kgtu.kg",
        "office":   "Каб. 312",
        "bio":      "Старший преподаватель кафедры ПОКС. Ведёт курсы по машинному обучению и анализу данных.",
        "initials": "СК",
    },
    {
        "id":       13,
        "name":     "Мусабаев Эмильбек Бахытжанович",
        "position": "Старший преподаватель кафедры ПОКС",
        "subjects": ["Мобильная разработка", "Android", "Kotlin"],
        "email":    "musabaev@kgtu.kg",
        "office":   "Каб. 313",
        "bio":      "Старший преподаватель кафедры ПОКС. Специализируется в области мобильной разработки для платформы Android.",
        "initials": "МЭ",
    },
    {
        "id":       14,
        "name":     "Арзымбаева Аида Эмильевна",
        "position": "Старший преподаватель кафедры ПОКС",
        "subjects": ["Компьютерная графика", "UI/UX дизайн", "Figma"],
        "email":    "arzymbaeva@kgtu.kg",
        "office":   "Каб. 314",
        "bio":      "Старший преподаватель кафедры ПОКС. Ведёт курсы по компьютерной графике и проектированию пользовательских интерфейсов.",
        "initials": "АА",
    },
    {
        "id":       15,
        "name":     "Ашымова Айзада Жаасынбековна",
        "position": "Старший преподаватель кафедры ПОКС",
        "subjects": ["Тестирование ПО", "QA", "Автоматизация тестирования"],
        "email":    "ashymova@kgtu.kg",
        "office":   "Каб. 315",
        "bio":      "Старший преподаватель кафедры ПОКС. Специализируется в области тестирования программного обеспечения и обеспечения качества.",
        "initials": "АА",
    },
    {
        "id":       16,
        "name":     "Беккулова Кыял Абдыкапаровна",
        "position": "Старший преподаватель кафедры ПОКС",
        "subjects": ["DevOps", "Docker", "CI/CD", "Kubernetes"],
        "email":    "bekkulova@kgtu.kg",
        "office":   "Каб. 316",
        "bio":      "Старший преподаватель кафедры ПОКС. Ведёт курсы по DevOps практикам и контейнеризации.",
        "initials": "БК",
    },
    {
        "id":       17,
        "name":     "Марченко Татьяна Николаевна",
        "position": "Старший преподаватель кафедры ПОКС",
        "subjects": ["Иностранный язык в IT", "Техническая документация"],
        "email":    "marchenko@kgtu.kg",
        "office":   "Каб. 317",
        "bio":      "Старший преподаватель кафедры ПОКС. Ведёт курс иностранного языка для IT-специалистов.",
        "initials": "МТ",
    },
    {
        "id":       18,
        "name":     "Турсалиева Эльнура Нарынбековна",
        "position": "Старший преподаватель кафедры ПОКС",
        "subjects": ["Искусственный интеллект", "Нейронные сети", "Deep Learning"],
        "email":    "tursalieva@kgtu.kg",
        "office":   "Каб. 318",
        "bio":      "Старший преподаватель кафедры ПОКС. Специализируется в области искусственного интеллекта и нейронных сетей.",
        "initials": "ТЭ",
    },
    {
        "id":       19,
        "name":     "Болотбек уулу Нурсултан",
        "position": "Старший преподаватель кафедры ПОКС",
        "subjects": ["Облачные технологии", "AWS", "Azure"],
        "email":    "bolotbek@kgtu.kg",
        "office":   "Каб. 319",
        "bio":      "Старший преподаватель кафедры ПОКС. Ведёт курсы по облачным технологиям и сервисам.",
        "initials": "БН",
    },
    {
        "id":       20,
        "name":     "Абалиевой Айдай Доолоталиевна",
        "position": "Старший преподаватель кафедры ПОКС",
        "subjects": ["Программирование на Python", "Основы алгоритмизации"],
        "email":    "abalieva@kgtu.kg",
        "office":   "Каб. 320",
        "bio":      "Старший преподаватель кафедры ПОКС. Ведёт курсы по программированию на Python и основам алгоритмизации.",
        "initials": "АА",
    },
]

DISCIPLINES = [
    {"name": "Алгоритмы и структуры данных",              "semester": "1-2", "credits": 5,  "type": "Обязательная"},
    {"name": "Объектно-ориентированное программирование",  "semester": "2",   "credits": 4,  "type": "Обязательная"},
    {"name": "Дискретная математика",                      "semester": "1",   "credits": 4,  "type": "Обязательная"},
    {"name": "Базы данных",                                "semester": "3",   "credits": 5,  "type": "Обязательная"},
    {"name": "Операционные системы",                       "semester": "3",   "credits": 4,  "type": "Обязательная"},
    {"name": "Сетевые технологии",                         "semester": "4",   "credits": 4,  "type": "Обязательная"},
    {"name": "Информационная безопасность",                "semester": "4",   "credits": 4,  "type": "Обязательная"},
    {"name": "Web-разработка",                             "semester": "5",   "credits": 5,  "type": "Обязательная"},
    {"name": "Программная инженерия",                      "semester": "5",   "credits": 4,  "type": "Обязательная"},
    {"name": "Машинное обучение",                          "semester": "6",   "credits": 5,  "type": "По выбору"},
    {"name": "Мобильная разработка",                       "semester": "6",   "credits": 4,  "type": "По выбору"},
    {"name": "DevOps и контейнеризация",                   "semester": "7",   "credits": 4,  "type": "По выбору"},
    {"name": "Искусственный интеллект",                    "semester": "7",   "credits": 5,  "type": "По выбору"},
    {"name": "Компьютерная графика",                       "semester": "6",   "credits": 3,  "type": "По выбору"},
    {"name": "Тестирование программного обеспечения",      "semester": "5",   "credits": 3,  "type": "По выбору"},
    {"name": "Дипломная работа",                           "semester": "8",   "credits": 12, "type": "Обязательная"},
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
        {"time": "08:00–09:30", "subject": "Алгоритмы и структуры данных",   "group": "ПО-21", "room": "Каб. 201", "teacher": "Каткова С.Н."},
        {"time": "09:45–11:15", "subject": "Базы данных",                    "group": "ПО-22", "room": "Каб. 302", "teacher": "Садралиева Р.А."},
        {"time": "11:30–13:00", "subject": "Информационная безопасность",     "group": "ПО-41", "room": "Каб. 105", "teacher": "Макиева З.Д."},
        {"time": "14:00–15:30", "subject": "Web-разработка",                  "group": "ПО-31", "room": "Каб. 302", "teacher": "Стамкулова Г.К."},
    ],
    "Вторник": [
        {"time": "08:00–09:30", "subject": "Операционные системы",            "group": "ПО-22", "room": "Каб. 201", "teacher": "Жогаштиев Н.Т."},
        {"time": "09:45–11:15", "subject": "ООП",                             "group": "ПО-21", "room": "Каб. 302", "teacher": "Мусина И.Р."},
        {"time": "11:30–13:00", "subject": "Сетевые технологии",              "group": "ПО-32", "room": "Каб. 201", "teacher": "Искаков Р.Т."},
        {"time": "14:00–15:30", "subject": "Программная инженерия",           "group": "ПО-41", "room": "Каб. 301", "teacher": "Тен И.Г."},
    ],
    "Среда": [
        {"time": "08:00–09:30", "subject": "Машинное обучение",               "group": "ПО-41", "room": "Каб. 302", "teacher": "Сабаева К.К."},
        {"time": "09:45–11:15", "subject": "Алгоритмы и структуры данных",   "group": "ПО-22", "room": "Каб. 201", "teacher": "Каткова С.Н."},
        {"time": "11:30–13:00", "subject": "DevOps и контейнеризация",        "group": "ПО-42", "room": "Каб. 302", "teacher": "Беккулова К.А."},
        {"time": "14:00–15:30", "subject": "Дискретная математика",           "group": "ПО-21", "room": "Каб. 201", "teacher": "Валеева А.А."},
    ],
    "Четверг": [
        {"time": "08:00–09:30", "subject": "Базы данных",                    "group": "ПО-21", "room": "Каб. 302", "teacher": "Цой М.С."},
        {"time": "09:45–11:15", "subject": "Информационная безопасность",     "group": "ПО-42", "room": "Каб. 105", "teacher": "Макиева З.Д."},
        {"time": "11:30–13:00", "subject": "Искусственный интеллект",         "group": "ПО-41", "room": "Каб. 302", "teacher": "Турсалиева Э.Н."},
        {"time": "14:00–15:30", "subject": "Мобильная разработка",            "group": "ПО-41", "room": "Каб. 302", "teacher": "Мусабаев Э.Б."},
    ],
    "Пятница": [
        {"time": "08:00–09:30", "subject": "ООП",                             "group": "ПО-22", "room": "Каб. 302", "teacher": "Мусина И.Р."},
        {"time": "09:45–11:15", "subject": "Операционные системы",            "group": "ПО-21", "room": "Каб. 201", "teacher": "Жогаштиев Н.Т."},
        {"time": "11:30–13:00", "subject": "Программная инженерия",           "group": "ПО-31", "room": "Каб. 301", "teacher": "Тен И.Г."},
        {"time": "14:00–15:30", "subject": "Облачные технологии",             "group": "ПО-42", "room": "Каб. 302", "teacher": "Болотбек уулу Н."},
    ],
}

USERS = {
    "student": {"password": "student123", "name": "Студент", "role": "student"},
    "admin":   {"password": "admin123",   "name": "Администратор", "role": "admin"},
}

@app.route("/")
def index():
    return render_template("index.html", dept=DEPARTMENT, news=NEWS[:3], teachers=TEACHERS[:4])

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
            session["user"] = username
            session["name"] = user["name"]
            session["role"] = user["role"]
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
