from app import app, db, Question

# Only check the database, don't start the server
with app.app_context():
    print("Total questions:", Question.query.count())
    print("Categories:", [q.category for q in Question.query.all()])
