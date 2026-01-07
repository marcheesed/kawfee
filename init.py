from app import (
    CURRENT_POLICY_VERSION,
    User,
    app,
    db,
)


def create_admin(username, password):
    with app.app_context():
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            print(f"User '{username}' already exists.")
            return
        admin_user = User(
            username=username,
            is_admin=True,
            privacy_policy_version=CURRENT_POLICY_VERSION,
        )
        admin_user.set_password(password)
        db.session.add(admin_user)
        db.session.commit()
        print(f"Admin user '{username}' created successfully.")


if __name__ == "__main__":
    username = "admin"
    password = "password"
    create_admin(username, password)
