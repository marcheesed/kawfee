from app import (
    Badge,
    app,
    db,
)

with app.app_context():
    badges = [
        {
            "name": "staff",
            "description": "site staff member",
            "icon_url": "/static/icons/staff.svg",
        },
        {
            "name": "beta tester",
            "description": "participated in beta testing",
            "icon_url": "/static/icons/beta.svg",
        },
        {
            "name": "contributor",
            "description": "contributed content or code",
            "icon_url": "/static/icons/contributor.svg",
        },
        {
            "name": "warn",
            "description": "warned for something bad",
            "icon_url": "/static/icons/warn.svg",
        },
    ]
    for badge in badges:
        if not Badge.query.filter_by(name=badge["name"]).first():
            db.session.add(Badge(**badge))
            print(f"added badge: {badge['name']}")
    db.session.commit()
