from datetime import datetime, timezone

from extensions import db

user_badges = db.Table(
    "user_badges",
    db.Column("users_id", db.Integer, db.ForeignKey("users.id")),
    db.Column("badge_id", db.Integer, db.ForeignKey("badge.id")),
)

fanfic_comments_assoc = db.Table(
    "fanfic_comments_assoc",
    db.Column("fanfic_id", db.Integer, db.ForeignKey("fanfics.id"), primary_key=True),
    db.Column("comment_id", db.Integer, db.ForeignKey("comments.id"), primary_key=True),
)

fanfic_tags = db.Table(
    "fanfic_tags",
    db.Column("fanfic_id", db.Integer, db.ForeignKey("fanfics.id"), primary_key=True),
    db.Column("tag_id", db.Integer, db.ForeignKey("tags.id"), primary_key=True),
)


class Fanfic(db.Model):
    __tablename__ = "fanfics"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    fandom = db.Column(db.String)
    age_rating = db.Column(db.String)
    kudos = db.Column(db.Text)
    published_at = db.Column(db.Text)
    content = db.Column(db.Text)
    comments = db.relationship(
        "Comment", secondary=fanfic_comments_assoc, backref="fanfics"
    )
    tags = db.relationship("Tag", secondary=fanfic_tags, backref="fanfics")
    author = db.relationship("User", backref="fanfics")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    content = db.Column(db.Text)
    timestamp = db.Column(db.String)
    parent_id = db.Column(db.Integer, db.ForeignKey("comments.id"))
    fanfic_id = db.Column(db.Integer, db.ForeignKey("fanfics.id"))

    user = db.relationship("User", backref="comments", lazy=True)

    replies = db.relationship("Comment", backref=db.backref("parent", remote_side=[id]))


class Tag(db.Model):
    __tablename__ = "tags"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)


class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class SiteInfo(db.Model):
    __tablename__ = "site_info"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String)
    content = db.Column(db.Text)


class Kudos(db.Model):
    __tablename__ = "kudos"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    item_type = db.Column(db.String)
    item_id = db.Column(db.Integer)


class IPLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30))
    ip_address = db.Column(db.String(45))
    action = db.Column(db.String(50))
    timestamp = db.Column(db.DateTime, default=db.func.now())


class BannedIP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False)
    reason = db.Column(db.String(255))
    banned_at = db.Column(db.DateTime, default=db.func.now())


class BannedUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), unique=True)
    reason = db.Column(db.String(255))
    banned_at = db.Column(db.DateTime, default=db.func.now())

    user = db.relationship("User", backref="banned_user")


class InviteCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(32), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.now())
    used = db.Column(db.Boolean, default=False)
    used_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    used_at = db.Column(db.DateTime, nullable=True)

    creator_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    creator = db.relationship(
        "User", foreign_keys=[creator_id], backref="created_invite_codes"
    )
    used_by_user = db.relationship(
        "User", foreign_keys=[used_by], backref="used_invite_codes"
    )


class Badge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(255))
    icon_url = db.Column(db.String(255))
