from app import app, db
from app.models import User
import click

@click.group()
def cli():
    pass

@cli.command('initdb')
def initdb():
    with app.app_context():
        db.create_all()
        print('Database initialized successfully!')

@cli.command('create_admin')
@click.argument('username')
@click.argument('password')
def create_admin(username, password):
    with app.app_context():
        if User.query.filter_by(username=username).first():
            print('Admin user already exists!')
            return
        
        admin = User(
            username=username,
            email=f'{username}@grabItDone.com',
            role='admin',
            first_name='Admin',
            last_name='User',
            verified=True,
            verification_status='approved'
        )
        admin.set_password(password)
        db.session.add(admin)
        db.session.commit()
        print('Admin user created successfully!')

if __name__ == '__main__':
    cli()