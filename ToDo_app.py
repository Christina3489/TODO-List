
from unicodedata import category
from flask import Flask, render_template, redirect, request, flash, session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, DateField, SelectField, TextAreaField 
from wtforms.validators import DataRequired, EqualTo
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy 
from flask_login import LoginManager, current_user, login_user, logout_user, login_required
from models import Category
from flask_login import UserMixin

import sqlite3

conn = sqlite3.connect('sqlite://C:/Users/chris/Downloads/sqlite-dll-win64-x64-3420000')

cursor = conn.cursor()

# Create the 'user' table
create_user_table_query = '''
CREATE TABLE IF NOT EXISTS user (
  user_id INTEGER PRIMARY KEY AUTOINCREMENT,
  username VARCHAR(255) NOT NULL,
  password VARCHAR(255) NOT NULL,
  full_name VARCHAR(255)
)
'''
cursor.execute(create_user_table_query)

# Create the 'task' table
create_task_table_query = '''
CREATE TABLE IF NOT EXISTS task (
    task_id INTEGER PRIMARY KEY,
    task_name VARCHAR(255),
    due_date DATE,
    priority VARCHAR(50),
    status VARCHAR(50),
    assignee_id INTEGER,
    category VARCHAR(255),
    notes TEXT,
    FOREIGN KEY (assignee_id) REFERENCES user(user_id)
)
'''
cursor.execute(create_task_table_query)

# Commit the changes and close the connection
conn.commit()
conn.close()



app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://C:/Users/chris/Downloads/sqlite-dll-win64-x64-3420000'
bcrypt = Bcrypt()
db = SQLAlchemy(app)


login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Simulating a user database


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Define the CreateTaskForm class
class CreateTaskForm(FlaskForm):
    task_id = StringField('Task ID', validators=[DataRequired()])
    task_name = StringField('Task Name', validators=[DataRequired()])
    due_date = DateField('Due Date', validators=[DataRequired()])
    priority = SelectField('Priority', choices=[('low', 'Low'), ('medium', 'Medium'), ('high', 'High')], validators=[DataRequired()])
    status = SelectField('Status', choices=[('pending', 'Pending'), ('in_progress', 'In Progress'), ('completed', 'Completed')], validators=[DataRequired()])
    assignee = StringField('Assignee', validators=[DataRequired()])
    category = SelectField('Category', choices=[('personal', 'Personal'), ('job', 'Job'), ('academic', 'Academic'), ('other', 'Other')], validators=[DataRequired()])
    notes = TextAreaField('Notes') 
  
class FilterForm(FlaskForm):
    category = SelectField('Category', choices=[('personal', 'Personal'), ('job', 'Job'), ('academic', 'Academic'), ('other', 'Other')], validators=[DataRequired()])
    priority = SelectField('Priority', choices=[('low', 'Low'), ('medium', 'Medium'), ('high', 'High')], validators=[DataRequired()])
    status = SelectField('Status', choices=[('pending', 'Pending'), ('in_progress', 'In Progress'), ('completed', 'Completed')], validators=[DataRequired()])

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model):
    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(100))


class Task(db.Model):
    task_id = db.Column(db.Integer, primary_key=True)
    task_name = db.Column(db.String(255), nullable=False)
    due_date = db.Column(db.Date, nullable=False)
    priority = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(50), nullable=False)
    assignee_id = db.Column(db.Integer, db.ForeignKey('user.user_id'))
    category = db.Column(db.String(255), nullable=False)
    notes = db.Column(db.Text)
    assignee = db.relationship('User', backref='tasks')


@app.route('/')
def home():
    return render_template('Welcome.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        confirm_password = form.confirm_password.data

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        print("Redirecting to login page")  # Add this print statement
        return redirect('/login')

    print("Registration form did not validate")  # Add this print statement
    # Retrieve the form validation errors
    errors = form.errors
    print(errors)  # Print the validation errors

    flash('Registration failed. Please check the entered data.', 'error')
    return render_template('register.html', form=form)



@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    try:
        if request.method == 'POST':
            username = form.username.data
            password = form.password.data
            print(f'Error')
            user = User.query.filter_by(username=username).first()
            if user and bcrypt.check_password_hash(user.password, password):
                flash('Login successful!', 'success')
                session['user_id'] = user.user_id
                print(f'No error during login')
                # Perform the necessary tasks to authenticate the user and redirect to their personal to-do list
                return redirect('/task_list')
            else:
                print(f'Error during login')
                flash('Invalid username or password. Please try again.', 'error')
    except Exception as e:
        flash(f'An error occurred during login: {str(e)}', 'error')
        # Print the error to the console for debugging purposes
        print(f'Error during login: {str(e)}')
    print(f'before return')
    return render_template('login.html', form=form, current_user=current_user)

# Logout route
@app.route('/logout')
def logout():
    # Clear the user session and perform logout logic
    session.clear()
    return redirect('/')



@app.route('/tasks/create', methods=['GET', 'POST'])
def create_task():
    form = CreateTaskForm()
    if form.validate_on_submit():
        # Retrieve form data
        task_id = form.task_id.data
        task_name = form.task_name.data
        due_date = form.due_date.data
        priority = form.priority.data
        status = form.status.data
        assignee = form.assignee.data
        category = form.category.data
        notes = form.notes.data

        # Check if the assignee exists in the database
        assignee_user = User.query.filter_by(username=assignee).first()
        if assignee_user is None:
            flash('Invalid assignee. Please enter a valid username.', 'error')
            return redirect('/tasks/create')

        # Create a new task instance
        new_task = Task(
            task_id=task_id,
            task_name=task_name,
            due_date=due_date,
            priority=priority,
            status=status,
            assignee_id=assignee_user.user_id,
            category=category,
            notes=notes
        )

        # Save the task to the database
        db.session.add(new_task)
        db.session.commit()

        flash('Task created successfully!', 'success')
        return redirect('/task_list')

    return render_template('create_task.html', form=form, current_user=current_user)

@app.route('/tasks/edit/<int:task_id>', methods=['GET', 'POST'])



@app.route('/task_list', methods=['GET', 'POST'])
def task_list():
    form = FilterForm()
    categories = ['Personal', 'Job', 'Academic', 'Other']
    

    form.category.choices = [('All', 'All')] + [('personal', 'Personal'), ('job', 'Job'), ('academic', 'Academic'), ('other', 'Other')]
    form.status.choices = [('All', 'All')] + [('pending', 'Pending'), ('in_progress', 'In Progress'), ('completed', 'Completed')]
    form.priority.choices = [('All', 'All'), ('High', 'High'), ('Medium', 'Medium'), ('Low', 'Low')]

    category_filter = form.category.data
    status_filter = form.status.data
    priority_filter = form.priority.data

    tasks = Task.query

    if category_filter != 'All':
        tasks = tasks.filter_by(category=category_filter)
    if status_filter != 'All':
        tasks = tasks.filter_by(status=status_filter)
    if priority_filter != 'All':
        tasks = tasks.filter_by(priority=priority_filter)

    tasks = tasks.all()


    return render_template('task_filter.html', tasks=tasks, form=form)


@app.route('/edit_task/<int:task_id>', methods=['GET', 'POST'])
def edit_task(task_id):
    task = Task.query.get(task_id)
    assignee_username = task.assignee.username if task.assignee else ''  # Retrieve the username or assign an empty string if assignee is None

    form = CreateTaskForm(obj=task)
    form.assignee.data = assignee_username  # Set the assignee field in the form to the username

    if request.method == 'POST':
        print(f'In edit')
        # Update the task data based on the form inputs
        task.task_name = request.form['task_name']
        task.due_date = request.form['due_date']
        task.priority = request.form['priority']
        task.status = request.form['status']
        task.assignee = User.query.filter_by(username=form.assignee.data).first()  # Retrieve the User object based on the username
        print("before  ass")
        print(task.assignee)
        task.category = request.form['category']
        task.notes = request.form['notes']
        db.session.commit()
        flash('Task updated successfully!', 'success')
        return redirect('/task_list')

    return render_template('edit_task.html', form=form, current_user=current_user)


@app.route('/tasks/delete/<int:task_id>', methods=['POST'])
def delete_task(task_id):
    # Retrieve the task from the database
    task = Task.query.get(task_id)
    print(f'In Delete')

    if task:
        # Delete the task from the database
        print("In Delete1")
        db.session.delete(task)
        db.session.commit()
        flash('Task deleted successfully!', 'success')
    else:
        print(f'In Delete2')
        flash('Task not found!', 'error')
    print(f'In Delete3')
    return redirect('/task_list')


if __name__ == '__main__':
    conn_str = 'sqlite://C:/Users/chris/Downloads/sqlite-dll-win64-x64-3420000'
    db.create_all()
    db.session.commit()
    app.run(debug=True)
