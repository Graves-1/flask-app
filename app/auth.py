import functools
from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash
from app.db import get_db

bp = Blueprint('auth', __name__)

@bp.route('/', methods=('GET', 'POST', 'PUT', 'DELETE'))
def register():
    if request.method == 'POST':
        show_id = request.form['show_id']
        show_type = request.form['type']
        title = request.form['title']
        director = request.form['director']
        cast = request.form['cast']
        country = request.form['country']
        date_added = request.form['date_added']
        release_year = request.form['release_year']
        rating = request.form['rating']
        duration = request.form['duration']
        listed_in = request.form['listed_in']
        description = request.form['description']
        read_show_id = request.form['read_id']
        delete_id = request.form['delete_id']
        update_id = request.form['update_id']
        update_type = request.form['utype']
        update_title = request.form['utitle']
        update_director = request.form['udirector']
        update_cast = request.form['ucast']
        update_country = request.form['ucountry']
        update_date_added = request.form['udate_added']
        update_release_year = request.form['urelease_year']
        update_rating = request.form['urating']
        update_duration = request.form['uduration']
        update_listed_in = request.form['listed_in']
        update_description = request.form['udescription']
        show = None
        db = get_db()
        error = None
        error2 = None
        error3 = None
        
        if not show_id:
            error2 = 'All fields are required'
        elif not show_type:
            error2 = 'All fields are required'
        elif not title:
            error2 = 'All fields are required'
        elif not director:
            error2 = 'All fields are required'
        elif not cast:
            error2 = 'All fields are required'
        elif not country:
            error2 = 'All fields are required'
        elif not date_added:
            error2 = 'All fields are required'
        elif not release_year:
            error2 = 'All fields are required'
        elif not rating:
            error2 = 'All fields are required'
        elif not duration:
            error2 = 'All fields are required'
        elif not listed_in:
            error2 = 'All fields are required'
        elif not description:
            error2 = 'All fields are required'
        elif db.execute(
            'SELECT show_id FROM attributes WHERE show_id = ?', (show_id,)
        ).fetchone() is not None:
            error = 'Show is already in use'
            error2 = 'For logic'
            flash(error)
            
        if error2 is None:
            db.execute(
                'INSERT INTO attributes (show_id, type, title, director, cast, country, date_added, release_year, rating, duration, listed_in, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (show_id, show_type, title, director, cast, country, date_added, release_year, rating, duration, listed_in, description)
            )
            db.commit()
                #        'INSERT INTO user (username, password) VALUES (?, ?)',
         #       (show_type, title)
     #       return render_template('auth/register.html')
        if read_show_id:
            show = db.execute (
                'SELECT *'
                ' FROM attributes '
                ' WHERE show_id = ? ',
                (read_show_id,)
            ).fetchall()
            if show is not None:
                return render_template('auth/register.html', show=show)
            error = 'There is no show with that id in the database'
            flash(error)

        if delete_id:
            show = db.execute (
                'DELETE'
                ' FROM attributes '
                ' WHERE show_id = ? ',
                (delete_id,)
            )
            db.commit()

        if not update_id:
            error3 = 'yes'
        if not update_type:
            error3 = 'yes'
        if not update_title:
            error3 = 'yes'

        if error3 is None:
            show = db.execute (
                'UPDATE attributes SET show_id = ?, type = ?, title = ?, director = ?, cast = ?, country = ?, date_added = ?, release_year = ?, rating = ?, duration = ?, listed_in = ?, description = ? WHERE show_id = ?', (update_id, update_type, update_title, update_director, update_cast, update_country, update_date_added, update_release_year, update_rating, update_duration, update_listed_in, update_description, update_id)
            )
            db.commit()

        
    return render_template('auth/register.html', show=None)

#@bp.route('/',methods=('GET'))
#def read():
 #   if request.method == 'GET':
  #      show_id = request.form['read_id']
   #     error = 'default'
        #flash(error)
    #    if not show_id:
     #       error = 'Input show ID'
       # elif db.execute(
      #      'SELECT * FROM attributes WHERE show_id = ?', (read_id,)
       # )db.commit()
       # flash(error)
   #return render_template('auth/register.html')





            
        

@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        user = db.execute(
            'SELECT * FROM user WHERE username = ?', (username,)
        ).fetchone()

        if user is None:
            error = 'Incorrect username.'
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password.'

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('review.dashboard'))

        flash(error)

    return render_template('auth/login.html')

@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('review.home'))

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view
