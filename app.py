import json
import math
import os
import random
import re
import secrets
import string
from datetime import datetime, timezone
from functools import wraps

import bcrypt
import bleach
from bleach.css_sanitizer import CSSSanitizer
from flask import (
    Flask,
    abort,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask.typing import ResponseReturnValue
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
)
from flask_wtf import CSRFProtect
from PIL import Image
from sqlalchemy import func, or_, text
from sqlalchemy.orm import joinedload
from werkzeug.utils import secure_filename

from extensions import db
from models import (
    Badge,
    BannedIP,
    BannedUser,
    Comment,
    Fanfic,
    InviteCode,
    IPLog,
    Kudos,
    Note,
    SiteInfo,
    Tag,
    fanfic_tags,
    user_badges,
)
from properties import (
    ALLOWED_CSS_PROPERTIES,
    CURRENT_POLICY_VERSION,
    allowed_attributes,
    allowed_tags,
)

app = Flask(__name__, static_folder="static")
login_manager = LoginManager()
login_manager.init_app(app)
app.secret_key = "your-secret-key"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///kawfee.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = "static/profile_pics"
if not os.path.exists(app.config["UPLOAD_FOLDER"]):
    os.makedirs(app.config["UPLOAD_FOLDER"])
app.jinja_env.finalize = lambda x: x if x is not None else ""
csrf = CSRFProtect(app)
db.init_app(app)

with app.app_context():
    db.create_all()

# class user here instead of models.py bc it wont import verify password >:[


class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    password_hash = db.Column(db.String, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    bio = db.Column(db.String(500))
    pfp = db.Column(db.String)
    custom_css = db.Column(db.String(2000))
    badges = db.relationship("Badge", secondary=user_badges, backref="users")
    privacy_policy_version = db.Column(db.Integer, default=0)

    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(
            password.encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8")

    def verify_password(self, password):
        return bcrypt.checkpw(
            password.encode("utf-8"), self.password_hash.encode("utf-8")
        )


# -------- helpers --------


@login_manager.user_loader
def flask_load_user(user_id):
    return User.query.get(int(user_id))


def sanitize_css(css):
    css = re.sub(r"@import[^;]*;", "", css, flags=re.IGNORECASE)
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.DOTALL)
    declarations = css.split(";")
    sanitized_declarations = []

    for decl in declarations:
        decl = decl.strip()
        if not decl:
            continue
        if ":" not in decl:
            continue
        prop, value = decl.split(":", 1)
        prop = prop.strip().lower()
        value = value.strip()

        if re.search(r"expression|url\(", value, re.IGNORECASE):
            if prop == "background-image":
                pass
            else:
                continue

        if prop in ALLOWED_CSS_PROPERTIES:
            sanitized_declarations.append(f"{prop}: {value}")

    return "; ".join(sanitized_declarations)


class NoImportCSSSanitizer(CSSSanitizer):
    def sanitize_css_import(self, css):
        css = re.sub(r"@import[^;]*;", "", css, flags=re.IGNORECASE)
        return super().sanitize_css(css)


css_sanitizer_instance = NoImportCSSSanitizer(
    allowed_css_properties=ALLOWED_CSS_PROPERTIES
)
css_sanitizer_instance = CSSSanitizer(allowed_css_properties=ALLOWED_CSS_PROPERTIES)


def logged_in():
    return g.current_user is not None


def extract_css_declarations(css_block):
    match = re.search(r"\{([^}]*)\}", css_block, re.DOTALL)
    if match:
        return match.group(1)
    return css_block


def sanitize_content(content):
    return bleach.clean(
        content,
        tags=allowed_tags,
        attributes=allowed_attributes,
        css_sanitizer=css_sanitizer_instance,
        strip=True,
    )


def is_ip_banned(ip):
    return BannedIP.query.filter_by(ip_address=ip).first() is not None


def is_user_banned(user_id):
    return BannedUser.query.filter_by(user_id=user_id).first() is not None


def get_client_ip():
    if request.headers.getlist("X-Forwarded-For"):
        ip = request.headers.getlist("X-Forwarded-For")[0].split(",")[0]
    else:
        ip = request.remote_addr
    return ip


def generate_unique_id(length=8):
    characters = string.ascii_letters + string.digits
    return "".join(random.choices(characters, k=length))


def get_unique_custom_id():
    while True:
        new_id = generate_unique_id()
        if not Fanfic.query.filter_by(custom_id=new_id).first():
            return new_id


def log_ip(action):
    user_id = session.get("user_id")
    if not user_id:
        return

    user = User.query.get(user_id)
    if not user:
        return

    ip = get_client_ip()
    ip_log = IPLog(username=user.username, ip_address=ip, action=action)
    db.session.add(ip_log)
    db.session.commit()


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = User.query.get(session.get("user_id"))
        if not user or not user.is_admin:
            abort(403)  # FORBIDDEEN
        return f(*args, **kwargs)

    return decorated_function


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated_function


def get_form_value(key):
    value = request.form.get(key)
    return value if value is not None else ""


def get_comments_tree(fanfic_id):
    comments = (
        Comment.query.filter_by(fanfic_id=fanfic_id)
        .order_by(Comment.timestamp.asc())
        .all()
    )

    def build_tree(parent_id=None):
        branch = []
        for comment in comments:
            if comment.parent_id == parent_id:
                branch.append({"comment": comment, "replies": build_tree(comment.id)})
        return branch

    return build_tree()


def get_or_create_tag(session, tag_name):
    result = (
        session.execute(
            text("SELECT * FROM tags WHERE name = :name"), {"name": tag_name}
        )
        .mappings()
        .fetchone()
    )

    if result:
        tag_id = result["id"]
        tag = Tag.query.get(tag_id)
        if tag:
            return tag
        else:
            tag = Tag(id=tag_id, name=tag_name)
            session.add(tag)
            session.flush()
            return tag
    else:
        session.execute(
            text("INSERT INTO tags (name) VALUES (:name)"), {"name": tag_name}
        )
        session.flush()
        result = (
            session.execute(
                text("SELECT * FROM tags WHERE name = :name"), {"name": tag_name}
            )
            .mappings()
            .fetchone()
        )
        if result:
            tag_id = result["id"]
            return Tag.query.get(tag_id) or Tag(id=tag_id, name=tag_name)
        else:
            raise Exception(f"Failed to create or fetch tag: {tag_name}")


@app.errorhandler(400)
def request_failed(e):
    return render_template("errors/400.html"), 400


@app.errorhandler(401)
def authorization_failed(e):
    return render_template("errors/401.html"), 401


@app.errorhandler(403)
def access_denied(e):
    return render_template("errors/403.html"), 403


@app.errorhandler(404)
def page_not_found(e):
    return render_template("errors/404.html"), 404


@app.errorhandler(500)
def csrf_token(e):
    return render_template("errors/500.html"), 500


# -------- basic routes --------


@app.route("/")
def index():
    page = request.args.get("page", 1, type=int)
    search_query = request.args.get("search", "", type=str).strip()
    per_page = 5
    fanfic_query = Fanfic.query
    if search_query:
        fanfic_query = fanfic_query.filter(Fanfic.title.ilike(f"%{search_query}%"))
    pagination = fanfic_query.paginate(page=page, per_page=per_page, error_out=False)
    fanfics = pagination.items
    total_pages = pagination.pages
    current_page = pagination.page
    site_info = SiteInfo.query.first()
    top_tags = (
        db.session.query(Tag)
        .join(fanfic_tags)
        .group_by(Tag.id)
        .order_by(func.count(fanfic_tags.c.fanfic_id).desc())
        .limit(5)
        .all()
    )
    return render_template(
        "index.html",
        fanfics=fanfics,
        site_info=site_info,
        total_pages=total_pages,
        current_page=current_page,
        top_tags=top_tags,
        search=search_query,
    )


@app.route("/info")
def get_site_info():
    site_info = SiteInfo.query.first()
    return render_template("site_info.html", site_info=site_info)


@app.route("/terms")
def terms():
    return render_template("terms.html")


@app.route("/privacy")
def privacy():
    return render_template("privacy.html")


# -------- fanfics --------


@app.route("/upload", methods=["GET", "POST"])
def upload_fanfic():
    tags = []

    if request.method == "POST":
        title = request.form.get("title")
        author_id = None
        user_id = session.get("user_id")
        if user_id:
            user = User.query.get(user_id)
            author_id = user.username if user else "Anonymous"
        else:
            author_id = "Anonymous"

        fandom = request.form.get("fandom")
        age_rating = request.form.get("age_rating")
        kudos = request.form.get("kudos")
        content = request.form.get("content")

        new_fanfic = Fanfic(
            title=title,
            author_id=author_id,
            fandom=fandom,
            age_rating=age_rating,
            kudos=kudos,
            content=content,
        )

        db.session.add(new_fanfic)
        db.session.flush()

        tags_json = request.form.get("tags", "[]")
        try:
            combined_tags = json.loads(tags_json)
            if not isinstance(combined_tags, list):
                combined_tags = []
        except json.JSONDecodeError:
            combined_tags = []

        new_tag = request.form.get("new_tag", "").strip()
        if new_tag and new_tag not in combined_tags:
            combined_tags.append(new_tag)

        unique_tags = set(combined_tags)
        tag_ids = {}
        for tag in unique_tags:
            tag_id = get_or_create_tag(db.session, tag)
            tag_ids[tag] = tag_id

        for tag_id in tag_ids.values():
            db.session.execute(
                text(
                    "INSERT OR IGNORE INTO fanfic_tags (fanfic_id, tag_id) VALUES (:fanfic_id, :tag_id)"
                ),
                {"fanfic_id": new_fanfic.id, "tag_id": tag_id},
            )

        db.session.commit()

        return redirect(url_for("index"))

    return render_template("fanfic/upload.html", tags=tags)


@app.route("/fanfics/<int:id>", methods=["GET"])
def view_fanfic(id):
    fanfic = Fanfic.query.get_or_404(id)

    kudos_count = Kudos.query.filter_by(item_type="fanfic", item_id=id).count()

    kudos_users = (
        db.session.query(User)
        .join(Kudos, User.id == Kudos.user_id)
        .filter(Kudos.item_type == "fanfic", Kudos.item_id == id)
        .all()
    )
    kudos_usernames = [user.username for user in kudos_users]

    comments_tree = get_comments_tree(id)
    for comment in comments_tree:
        timestamp_str = getattr(comment, "timestamp", None) or comment.get("timestamp")
        if timestamp_str:
            try:
                comment["timestamp_dt"] = datetime.fromisoformat(timestamp_str)
            except (ValueError, TypeError):
                comment["timestamp_dt"] = timestamp_str

    visitor_username = None
    if "user_id" in session:
        current_user = User.query.get(session["user_id"])
        if current_user:
            visitor_username = current_user.username

    log_ip(f"{visitor_username} viewed {fanfic.title}")

    return render_template(
        "fanfic/view_fanfic.html",
        fanfic=fanfic,
        comments=comments_tree,
        kudos_count=kudos_count,
        kudos_usernames=kudos_usernames,
    )


@app.route("/fanfics/<int:id>/comment", methods=["POST"])
@login_required
def post_comment(id):
    content = request.form.get("content")
    parent_id = request.form.get("parent_id")

    user = g.current_user

    if not user or not user.is_authenticated:
        return redirect(url_for("login"))

    comment = Comment(
        user_id=user.id,
        content=content,
        timestamp=str(datetime.utcnow()),
        fanfic_id=id,
        parent_id=parent_id if parent_id else None,
    )

    db.session.add(comment)
    db.session.commit()

    return redirect(url_for("view_fanfic", id=id))


@app.route("/delete_comment/<int:comment_id>", methods=["POST"])
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    if g.current_user.is_authenticated and (
        g.current_user.id == comment.user_id or g.current_user.is_admin
    ):
        db.session.delete(comment)
        db.session.commit()
        print("Comment deleted successfully.", "success")
    else:
        print("You do not have permission to delete this comment.", "danger")
    return redirect(url_for("view_fanfic", id=comment.fanfic_id))


@app.route("/edit_comment/<int:comment_id>", methods=["GET"])
def edit_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    if g.current_user is None:
        print("You need to be logged in to edit comments.", "danger")
        return redirect(request.referrer or url_for("index"))
    if g.current_user.id != comment.user_id and not g.current_user.is_admin:
        print("You do not have permission to edit this comment.", "danger")
        return redirect(request.referrer or url_for("index"))
    return render_template("fanfic/edit_comment.html", comment=comment)


@app.route("/update_comment/<int:comment_id>", methods=["POST"])
@login_required
def update_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)

    user = g.current_user

    if not user or (user.id != comment.user_id and not user.is_admin):
        print("You do not have permission to edit this comment.", "danger")
        return redirect(request.referrer or url_for("index"))

    new_content = request.form.get("content")
    if not new_content:
        print("Content cannot be empty.", "danger")
        return redirect(url_for("edit_comment", comment_id=comment_id))

    comment.content = new_content
    comment.timestamp = str(datetime.now(timezone.utc))
    db.session.commit()
    print("Comment updated successfully.", "success")
    return redirect(url_for("view_fanfic", id=comment.fanfic_id))


@app.route("/fanfics/<int:fanfic_id>/delete", methods=["POST"])
@login_required
def delete_fanfic(fanfic_id):
    fanfic = Fanfic.query.get(fanfic_id)
    if not fanfic:
        abort(404)

    user = User.query.get(session.get("user_id"))
    if user is None:
        return redirect(url_for("login"))

    if fanfic.author != user.id and not user.is_admin:
        abort(403)
    db.session.delete(fanfic)
    db.session.commit()
    return redirect(url_for("index"))


@app.route("/kudo/<int:fid>", methods=["POST"])
def add_kudo(fid):
    if g.current_user is None:
        return redirect(url_for("login"))

    user = g.current_user
    existing_kudo = Kudos.query.filter_by(
        user_id=user.id, item_type="fanfic", item_id=fid
    ).first()

    if not existing_kudo:
        new_kudo = Kudos(user_id=user.id, item_type="fanfic", item_id=fid)
        db.session.add(new_kudo)
        db.session.commit()
        log_ip(action="kudo")
    else:
        pass

    return redirect(url_for("view_fanfic", id=fid))


@app.route("/edit/<int:id>", methods=["GET", "POST"])
def edit_fanfic(id):
    fanfic = Fanfic.query.get_or_404(id)
    if request.method == "POST":
        fanfic.title = request.form.get("title")
        fanfic.fandom = request.form.get("fandom")
        fanfic.age_rating = request.form.get("age_rating")
        fanfic.kudos = request.form.get("kudos")
        fanfic.content = request.form.get("content")
        tags_json = request.form.get("tags", "[]")
        try:
            submitted_tags = json.loads(tags_json)
            if not isinstance(submitted_tags, list):
                submitted_tags = []
        except json.JSONDecodeError:
            submitted_tags = []
        current_tags = [tag for tag in fanfic.tags]
        current_tag_names = [tag.name for tag in current_tags]
        tags_to_add = set(submitted_tags) - set(current_tag_names)
        tags_to_remove = set(current_tag_names) - set(submitted_tags)
        for tag in current_tags:
            if tag.name in tags_to_remove:
                fanfic.tags.remove(tag)
        for tag_name in tags_to_add:
            tag_obj = get_or_create_tag(db.session, tag_name)
            if tag_obj not in fanfic.tags:
                fanfic.tags.append(tag_obj)
        db.session.commit()
        return redirect(url_for("index"))
    current_tags = [tag.name for tag in fanfic.tags]
    return render_template("fanfic/edit_fanfic.html", fanfic=fanfic, tags=current_tags)


# -------- user shit --------


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    ip = get_client_ip()
    if is_ip_banned(ip):
        return "your ip has been banned!", 403
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = User.query.filter_by(username=username).first()
        if user:
            stored_hashed = user.password_hash
            if bcrypt.checkpw(password.encode("utf-8"), stored_hashed.encode("utf-8")):
                session["username"] = user.username
                session["user_id"] = user.id
                log_ip("login")
                return redirect(url_for("index"))
            else:
                error = "invalid credentials."
                log_ip("failed login")
        else:
            error = "User not found."
    return render_template("user/login.html", error=error)


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        invite_code_input = request.form.get("invite_code", "").strip()

        if invite_code_input:
            invite = InviteCode.query.filter_by(
                code=invite_code_input, used=False
            ).first()
            if not invite:
                error = "invalid or already used invite code!"
                return render_template("user/register.html", error=error)
        else:
            error = "invite code is required!"
            return render_template("user/register.html", error=error)

        if User.query.filter_by(username=username).first():
            error = "username already exists!!"
        else:
            user = User(
                username=username, privacy_policy_version=CURRENT_POLICY_VERSION
            )
            user.set_password(password)
            db.session.add(user)
            db.session.commit()

            if invite:
                invite.used = True
                invite.used_by = user.id
                invite.used_at = db.func.now()
                db.session.commit()

            session["user_id"] = user.id

            return redirect(url_for("index"))

    return render_template("user/register.html", error=error)


@app.route("/logout")
def logout():
    session.pop("user_id", None)
    return redirect(url_for("index"))


@app.route("/accept_terms", methods=["GET", "POST"])
def accept_terms():
    if request.method == "POST":
        if g.current_user:
            g.current_user.privacy_policy_version = CURRENT_POLICY_VERSION
            db.session.commit()
        return redirect(url_for("index"))
    return render_template("accept_terms.html")


@app.route("/profile/<username>", methods=["GET", "POST"])
def profile(username):
    user = User.query.filter_by(username=username).first_or_404()

    visitor_username = None
    if "user_id" in session:
        current_user = User.query.get(session["user_id"])
        if current_user:
            visitor_username = current_user.username

    log_ip(f"{visitor_username} viewed profile of {user.username}")

    is_owner = session.get("user_id") == user.id
    page = request.args.get("page", 1, type=int)
    per_page = 5
    total_fanfics = Fanfic.query.filter(Fanfic.author_id == user.username).count()

    fanfics = (
        Fanfic.query.filter(Fanfic.author_id == user.username)
        .order_by(Fanfic.id.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )

    total_pages = math.ceil(total_fanfics / per_page)

    if request.method == "POST":
        if not is_owner:
            return redirect(url_for("profile", username=user.username))

        bio = request.form.get("bio", "")
        user.bio = bio

        file = request.files.get("profile_picture")
        if file and file.filename:
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(filepath)
            user.profile_picture = filename

        db.session.commit()
        return redirect(url_for("profile", username=user.username, page=page))

    return render_template(
        "user/profile.html",
        user=user,
        is_owner=is_owner,
        visitor_username=visitor_username,
        profile_owner_username=user.username,
        fanfics=fanfics,
        page=page,
        total_pages=total_pages,
    )


@app.route("/edit_profile", methods=["GET", "POST"])
@login_required
def edit_profile() -> ResponseReturnValue:
    user = User.query.get(session.get("user_id"))
    if user is None:
        return redirect(url_for("login"))

    if request.method == "POST":
        custom_css_input = request.form.get("custom_css", "").strip()
        declarations = extract_css_declarations(custom_css_input)
        sanitized_declarations = sanitize_css(declarations)
        match = re.search(r"\{[^}]*\}", custom_css_input)
        if match:
            full_css = (
                custom_css_input[: match.start()]
                + "{"
                + sanitized_declarations
                + "}"
                + custom_css_input[match.end() :]
            )
        else:
            full_css = custom_css_input
        user.custom_css = full_css

        bio_html = request.form.get("bio", "").strip()
        user.bio = bio_html

        file = request.files.get("pfp")
        if file and file.filename:
            filename = secure_filename(file.filename)
            webp_filename = f"user_{user.id}.webp"
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            webp_filepath = os.path.join(app.config["UPLOAD_FOLDER"], webp_filename)
            file.save(filepath)
            try:
                img = Image.open(filepath)
                img.save(webp_filepath, "WEBP")
                os.remove(filepath)
                old_pfp = user.pfp
                if old_pfp and old_pfp != webp_filename:
                    old_pfp_path = os.path.join(app.config["UPLOAD_FOLDER"], old_pfp)
                    if os.path.exists(old_pfp_path):
                        os.remove(old_pfp_path)
                user.pfp = webp_filename
            except Exception as e:
                print(f"Error converting image: {e}")
                user.pfp = webp_filename

        new_username = request.form.get("username", "").strip()
        if new_username and new_username != user.username:
            existing_user = User.query.filter_by(username=new_username).first()
            if not existing_user:
                user.username = new_username
            else:
                error_message = "username already exists.. please choose a different one.ill make this nicer later."
                return render_template(
                    "user/edit_profile.html", user=user, error=error_message
                )

        try:
            db.session.commit()
        except Exception as e:
            print(f"Database commit error: {e}")

        return redirect(url_for("profile", username=user.username))
    return render_template("user/edit_profile.html", user=user)


@app.route("/delete_account", methods=["GET", "POST"])
@login_required
def delete_account():
    user_id = session.get("user_id")
    user = User.query.get(user_id)

    if not user:
        return redirect(url_for("login"))

    if request.method == "POST":
        password_input = request.form.get("password", "").strip()

        if not hasattr(user, "password_hash"):
            return redirect(url_for("login"))

        if not user.verify_password(password_input):
            error = "incorrect password."
            return render_template("user/delete_account.html", user=user, error=error)

        pfp_filename = user.pfp

        try:
            for fanfic in user.fanfics:
                db.session.delete(fanfic)
                for notes in user.notes:
                    db.session.delete(notes)
                for comments in fanfic.comments:
                    db.session.delete(comments)
            db.session.flush()

            db.session.delete(user)

            if pfp_filename:
                pfp_path = os.path.join(app.config["UPLOAD_FOLDER"], pfp_filename)
                if os.path.exists(pfp_path):
                    os.remove(pfp_path)

            db.session.commit()
        except Exception as e:
            print("Error during deletion:", e)
            db.session.rollback()
            error = "an error occurred. please try again later!"
            return render_template("user/delete_account.html", user=user, error=error)

        session.clear()
        return redirect(url_for("index"))

    return render_template("user/delete_account.html", user=user)


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    user = User.query.get(session.get("user_id"))
    if user is None:
        return redirect(url_for("login"))

    if request.method == "POST":
        current_password = request.form.get("current_password", "").strip()
        new_password = request.form.get("new_password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()

        if not user.check_password(current_password):
            return jsonify(
                {"success": False, "error": "current password is incorrect."}
            )

        if new_password != confirm_password:
            return jsonify({"success": False, "error": "new passwords do not match."})

        user.set_password(new_password)
        db.session.commit()
        return jsonify(
            {
                "success": True,
                "redirect_url": url_for("profile", username=user.username),
            }
        )

    return render_template("user/change_password.html")


@app.route("/settings/<username>")
def settings(username):
    if "user_id" not in session:
        return redirect(url_for("login"))

    return render_template("user/settings.html", user=current_user)


# -------- notes --------


@app.route("/notes")
def notes():
    if "user_id" not in session:
        return redirect(url_for("login"))

    log_ip("viewed notes")

    user = User.query.get(session["user_id"])
    user_notes = (
        Note.query.filter_by(user_id=user.id).order_by(Note.created_at.desc()).all()
    )
    return render_template("notes/notes.html", notes=user_notes)


@app.route("/notes/<int:note_id>")
def view_note(note_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    note = Note.query.get_or_404(note_id)
    if note.user_id != session["user_id"]:
        return "Unauthorized", 403

    return render_template("notes/view_note.html", note=note)


@app.route("/notes/<int:note_id>/edit", methods=["GET", "POST"])
def edit_note(note_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    note = Note.query.get_or_404(note_id)
    if note.user_id != session["user_id"]:
        return "Unauthorized", 403

    if request.method == "POST":
        content = request.form.get("content")
        if content:
            note.content = content
            db.session.commit()
            return redirect(url_for("view_note", note_id=note.id))

    return render_template("notes/edit_note.html", note=note)


@app.route("/notes/<int:note_id>/delete", methods=["POST"])
def delete_note(note_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    note = Note.query.get_or_404(note_id)
    if note.user_id != session["user_id"]:
        return "Unauthorized", 403

    db.session.delete(note)
    db.session.commit()
    return redirect(url_for("notes"))


@app.route("/notes/new", methods=["GET", "POST"])
def new_note():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        content = request.form.get("content")
        if content:
            note = Note(user_id=session["user_id"], content=content)
            db.session.add(note)
            db.session.commit()
            return redirect(url_for("notes"))

    return render_template("notes/new_note.html")


# -------- admin shit --------


@app.route("/admin")
@admin_required
def admin_panel():
    return render_template("admin/admin.html")


@app.route("/admin/fanfics")
@admin_required
def fanfics():
    search_query = request.args.get("search", "")
    page = int(request.args.get("page", 1))
    per_page = 10

    query = Fanfic.query.order_by(Fanfic.published_at.desc())

    if search_query:
        query = query.filter(Fanfic.title.ilike(f"%{search_query}%"))

    total = query.count()
    fanfics = query.offset((page - 1) * per_page).limit(per_page).all()

    total_pages = (total + per_page - 1) // per_page

    return render_template(
        "admin/fanfics.html",
        fanfics=fanfics,
        page=page,
        total_pages=total_pages,
        search=search_query,
    )


@app.route("/admin/site-info", methods=["POST"])
@admin_required
def update_site_info():
    title = request.form.get("title")
    content = request.form.get("content")

    try:
        site_info = SiteInfo.query.first()
        if not site_info:
            site_info = SiteInfo()

        if title is not None:
            site_info.title = title
        if content is not None:
            site_info.content = content

        db.session.add(site_info)
        db.session.commit()

        return jsonify(
            {"message": "Site info updated successfully.", "status": "success"}
        )
    except Exception as e:
        print("Error updating site info:", e)
        return jsonify({"message": "Error updating site info.", "status": "error"})

    return redirect("/admin/site-info")


@app.route("/admin/site-info", methods=["GET"])
@admin_required
def edit_site_info_page():
    site_info = SiteInfo.query.first()
    current_title = site_info.title if site_info else ""
    current_content = site_info.content if site_info else ""
    return render_template(
        "admin/site_info.html",
        current_title=current_title,
        current_content=current_content,
    )


@app.route("/admin/fanfics")
@admin_required
def admin_fanfics():
    search_query = request.args.get("search", "")
    page = int(request.args.get("page", 1))
    per_page = 10

    query = Fanfic.query.order_by(Fanfic.published_at.desc())

    if search_query:
        query = query.filter(Fanfic.content.ilike(f"%{search_query}%"))

    total = query.count()
    fanfics = query.offset((page - 1) * per_page).limit(per_page).all()

    total_pages = (total + per_page - 1) // per_page

    return render_template(
        "admin/fanfics.html",
        fanfics=fanfics,
        page=page,
        total_pages=total_pages,
        search=search_query,
    )


@app.route("/admin/assign_badge/<int:user_id>/<int:badge_id>", methods=["POST"])
@admin_required
def assign_badge(user_id, badge_id):
    user = User.query.get_or_404(user_id)
    badge = Badge.query.get_or_404(badge_id)
    if badge not in user.badges:
        user.badges.append(badge)
        db.session.commit()
    return redirect(url_for("users"))


@app.route("/admin/remove_badge/<int:user_id>/<int:badge_id>", methods=["POST"])
@admin_required
def remove_badge(user_id, badge_id):
    user = User.query.get_or_404(user_id)
    badge = Badge.query.get_or_404(badge_id)
    if badge in user.badges:
        user.badges.remove(badge)
        db.session.commit()
    return redirect(url_for("users"))


@app.route("/admin/ip_logs")
@admin_required
def ip_logs():
    search_query = request.args.get("search", "", type=str)
    page = request.args.get("page", 1, type=int)
    per_page = 10

    query = IPLog.query

    if search_query:
        query = query.filter(
            or_(
                IPLog.username.ilike(f"%{search_query}%"),
                IPLog.ip_address.ilike(f"%{search_query}%"),
            )
        )

    total = query.count()
    total_pages = (total + per_page - 1) // per_page

    logs = (
        query.order_by(IPLog.timestamp.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )

    return render_template(
        "admin/ip_logs.html",
        logs=logs,
        page=page,
        total_pages=total_pages,
        search=search_query,
    )


@app.route("/admin/user_ip_logs/<username>")
@admin_required
def user_ip_logs(username):
    page = request.args.get("page", 1, type=int)
    per_page = 20
    pagination = (
        IPLog.query.filter_by(username=username)
        .order_by(IPLog.timestamp.desc())
        .paginate(page=page, per_page=per_page)
    )

    logs = pagination.items

    return render_template(
        "admin/user_ip_logs.html", logs=logs, username=username, pagination=pagination
    )


@app.route("/admin/users", methods=["GET", "POST"])
@admin_required
def users():
    if request.method == "POST":
        user_id = int(request.form.get("user_id"))
        badge_id = int(request.form.get("badge_id"))
        user = User.query.get_or_404(user_id)
        badge = Badge.query.get_or_404(badge_id)
        if badge not in user.badges:
            user.badges.append(badge)
            db.session.commit()
        return redirect(url_for("users", page=request.args.get("page", 1)))

    search_query = request.args.get("search", "", type=str)
    page = request.args.get("page", 1, type=int)
    per_page = 10

    query = User.query
    if search_query:
        query = query.filter(User.username.ilike(f"%{search_query}%"))

    total = query.count()
    total_pages = (total + per_page - 1) // per_page

    users = (
        query.order_by(User.username)
        .offset((page - 1) * per_page)
        .limit(per_page)
        .options(joinedload(User.badges))
        .all()
    )

    users_with_ban_status = []
    for user in users:
        users_with_ban_status.append(
            {
                "user": user,
                "banned": bool(BannedUser.query.filter_by(user_id=user.id).first()),
                "badges": user.badges,
            }
        )

    badges = Badge.query.all()

    return render_template(
        "admin/users.html",
        users=users_with_ban_status,
        badges=badges,
        page=page,
        total_pages=total_pages,
        search=search_query,
    )


@app.route("/admin/ban_ip", methods=["POST"])
@admin_required
def ban_ip():
    ip_address = request.form["ip_address"]
    reason = request.form.get("reason", "")
    if not is_ip_banned(ip_address):
        ban = BannedIP(ip_address=ip_address, reason=reason)
        db.session.add(ban)
        db.session.commit()
    return redirect(url_for("ip_logs"))


@app.route("/admin/unban_ip/<ip_address>")
@admin_required
def unban_ip(ip_address):
    ban = BannedIP.query.filter_by(ip_address=ip_address).first()
    if ban:
        db.session.delete(ban)
        db.session.commit()
    return redirect(url_for("ip_logs"))


@app.route("/admin/ban_user/<int:user_id>", methods=["POST"])
@admin_required
def ban_user(user_id):
    reason = request.form.get("reason", "")
    if not is_user_banned(user_id):
        ban = BannedUser(user_id=user_id, reason=reason)
        db.session.add(ban)
        db.session.commit()
    return redirect(url_for("users"))


@app.route("/admin/unban_user/<int:user_id>")
@admin_required
def unban_user(user_id):
    ban = BannedUser.query.filter_by(user_id=user_id).first()
    if ban:
        db.session.delete(ban)
        db.session.commit()
    return redirect(url_for("users"))


@app.route("/admin/delete_user/<int:user_id>", methods=["POST"])
@admin_required
def delete_user(user_id):
    user = User.query.get(user_id)
    if not user:
        print("User not found.")
        return redirect(url_for("users"))

    pfp_filename = user.pfp

    try:
        for fanfic in user.fanfics:
            for comment in fanfic.comments:
                db.session.delete(comment)
            db.session.delete(fanfic)
        db.session.delete(user)

        if pfp_filename:
            pfp_path = os.path.join(app.config["UPLOAD_FOLDER"], pfp_filename)
            if os.path.exists(pfp_path):
                os.remove(pfp_path)

        db.session.commit()
        print("User deleted successfully.")
    except Exception as e:
        print("Error during admin deletion:", e)
        db.session.rollback()
        print("An error occurred while deleting the user.")
    return redirect(url_for("users"))


@app.route("/admin/generate_invite", methods=["GET", "POST"])
@admin_required
def generate_invite():
    if request.method == "POST":
        code = secrets.token_hex(8)
        invite = InviteCode(code=code, creator_id=session["user_id"])
        db.session.add(invite)
        db.session.commit()
        return render_template("admin/generated_invite.html", code=code)
    return render_template("admin/generate_invite.html")


@app.route("/admin/invite_codes")
@admin_required
def invite_codes():
    return render_template("admin/invite_codes.html")


@app.route("/admin/all_invite_codes")
@admin_required
def all_invite_codes():
    page = request.args.get("page", 1, type=int)
    per_page = 20
    pagination = InviteCode.query.order_by(InviteCode.created_at.desc()).paginate(
        page=page, per_page=per_page
    )
    codes = pagination.items

    return render_template(
        "admin/all_invite_codes.html", codes=codes, pagination=pagination
    )


@app.route("/admin/delete_invite_code/<int:code_id>", methods=["POST"])
@admin_required
def delete_invite_code(code_id):
    code = InviteCode.query.get_or_404(code_id)
    db.session.delete(code)
    db.session.commit()
    return redirect(url_for("all_invite_codes"))


@app.context_processor
def utility_processor():
    def is_ip_banned(ip):
        return BannedIP.query.filter_by(ip_address=ip).first() is not None

    def sanitize_content_for_template(content):
        return sanitize_content(content)

    return dict(
        is_ip_banned=is_ip_banned, sanitize_content=sanitize_content_for_template
    )


@app.before_request
def load_user():
    g.current_user = None
    if "user_id" in session:
        g.current_user = User.query.get(session["user_id"])


@app.before_request
def check_privacy_policy():
    if "user_id" in session:
        user = User.query.get(session["user_id"])
        if user and user.privacy_policy_version != CURRENT_POLICY_VERSION:
            if request.endpoint != "accept_terms":
                return redirect(url_for("accept_terms"))


@app.context_processor
def inject_user():
    current_user = getattr(g, "current_user", None)
    return dict(current_user=current_user)


@app.template_filter("nice_date")
def nice_date_filter(value):
    from datetime import datetime

    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value)
        except ValueError:
            return value
    elif isinstance(value, datetime):
        dt = value
    else:
        return value
    return dt.strftime("%B %d, %Y at %I:%M %p")


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5082)
