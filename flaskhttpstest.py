import os
import json
import base64
import secrets
import hashlib
import requests
import re
import uuid 
from flask import Flask, request, jsonify, render_template_string, redirect, render_template, send_from_directory, abort, send_file, session, url_for
from urllib.parse import urlencode 
from functools import wraps
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from datetime import datetime
from collections import Counter

# Liquid Daffodil Twitter clients
GLEEK_APP_LOGO = "https://pbs.twimg.com/client_application_images/553077/gleek_150x150.png"
GLEEK_APP_TITLE = "The coolest, fastest Bluesky app for Windows 8!"

 
 

issued_tokens = {}  # Maps oauth_token => token_secret, callback_url, etc.


app = Flask(__name__)
app.secret_key = "your_secret_key"

# Temporary in-memory token storage (replace with DB in production)
oauth_temp_tokens = {}


# Define path to your static assets folder
LEGACY_STATIC_FOLDER = os.path.join(
    app.root_path, 'static', 'authorization_files'
)

SESSION_FILE = "session_data.enc"
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY", "super_secret_key_please_change")  # secure this!
app.secret_key = "some-secret"

# --- Encryption helpers ---

def _derive_key():
    return hashlib.sha256(ENCRYPTION_KEY.encode()).digest()

def encrypt_session_data(data: dict) -> tuple:
    key = _derive_key()
    iv = secrets.token_bytes(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(json.dumps(data).encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encrypted = cipher.encryptor().update(padded) + cipher.encryptor().finalize()
    return base64.b64encode(iv).decode(), base64.b64encode(encrypted).decode()

def decrypt_session_data(iv_b64: str, enc_b64: str) -> dict:
    key = _derive_key()
    iv = base64.b64decode(iv_b64)
    encrypted = base64.b64decode(enc_b64)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decrypted = cipher.decryptor().update(encrypted) + cipher.decryptor().finalize()

    unpadder = padding.PKCS7(128).unpadder()
    unpadded = unpadder.update(decrypted) + unpadder.finalize()
    return json.loads(unpadded.decode())

def save_session(session: dict):
    iv, enc = encrypt_session_data(session)
    with open(SESSION_FILE, 'w') as f:
        f.write(iv + "\n" + enc)

def load_session() -> dict:
    if not os.path.exists(SESSION_FILE):
        return None
    with open(SESSION_FILE, 'r') as f:
        iv = f.readline().strip()
        enc = f.readline().strip()
    return decrypt_session_data(iv, enc)

# --- OAuth route ---

@app.route('/oauth/access_token', methods=['POST', 'GET'])
def oauth_access_token():
    username = request.form.get('x_auth_username')
    password = request.form.get('x_auth_password')
    if not username or not password:
        return "Missing x_auth_username or x_auth_password", 400

    if username.startswith('@'):
        username = username[1:]
    if '.' not in username:
        username += '.bsky.social'

    try:
        response = requests.post("https://bsky.social/xrpc/com.atproto.server.createSession",
                                 json={"identifier": username, "password": password}, timeout=10, verify=False)
        response.raise_for_status()
        session_data = response.json()

        token = secrets.token_hex(16)
        session_info = {
            "token": token,
            "jwt": session_data["accessJwt"],
            "did": session_data["did"],
            "handle": session_data.get("handle", username),
            "username": username,
            "password": password  # optional: only if you want to re-login
        }

        save_session(session_info)
        return f"oauth_token={token}&oauth_token_secret=unused&user_id={session_data['did']}&screen_name={username}"
    except requests.HTTPError as e:
        return f"error_code=401&error=invalid_login&message={e.response.text}", 401

# --- Auth wrapper ---

def require_session(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        session = load_session()
        if not session or "jwt" not in session:
            return jsonify({"error": "Session not found or expired"}), 401
        request.session = session
        return func(*args, **kwargs)
    return wrapper

# --- Test endpoint using saved session ---

@app.route('/1.1/account/verify_credentials.json', methods=['GET'])
@require_session
def verify_credentials():
    session = request.session
    headers = {"Authorization": f"Bearer {session['jwt']}"}

    try:
        # Step 1: Get current session info to retrieve DID
        session_resp = requests.get("https://bsky.social/xrpc/com.atproto.server.getSession", headers=headers, timeout=10, verify=False)
        session_resp.raise_for_status()
        bsky_session = session_resp.json()
        did = bsky_session.get("did")
        handle = bsky_session.get("handle")

        # Step 2: Use DID to get full profile info
        profile_resp = requests.get("https://bsky.social/xrpc/app.bsky.actor.getProfile", params={"actor": did}, headers=headers, timeout=10, verify=False)
        profile_resp.raise_for_status()
        profile = profile_resp.json()

        twitter_user = {
            "id_str": did,
            "name": profile.get("displayName", handle),
            "screen_name": handle,
            "location": "",
            "profile_background_image_url_https": "https://i.sstatic.net/aE5oM.jpg",
            "profile_background_image_url": "http://i.sstatic.net/aE5oM.jpg",
            "profile_background_color": "333333",
            "description": profile.get("description", ""),
            "followers_count": profile.get("followersCount", 0),
            "friends_count": profile.get("followsCount", 0),
            "statuses_count": profile.get("postsCount", 0),
            "profile_image_url_https": profile.get("avatar", "https://abs.twimg.com/sticky/default_profile_images/default_profile_normal.png"),
            "profile_banner_url": profile.get("banner", "")
        }

        return jsonify(twitter_user)

    except Exception as e:
        return jsonify({"error": "Bluesky session invalid", "details": str(e)}), 401

 

def format_twitter_date(iso_date):
    try:
        return datetime.strptime(iso_date, "%Y-%m-%dT%H:%M:%S.%fZ").strftime("%a %b %d %H:%M:%S +0000 %Y")
    except:
        return datetime.utcnow().strftime("%a %b %d %H:%M:%S +0000 %Y") 

def hash_to_id(s, base_ts=1288834974657):
    """
    Generate a realistic fake 64-bit Twitter-like Snowflake ID from a string.
    Ensures:
    - Chronological sorting (based on stable hash-derived timestamp)
    - Unique and deterministic
    """
    h = hashlib.sha1(s.encode()).hexdigest()
    hash_prefix = int(h[:8], 16)

    # Simulate timestamp within reasonable range from Twitter epoch
    timestamp_ms = base_ts + (hash_prefix % (10**10)) // 1000
    machine_id = 1 << 12
    sequence = int(h[8:12], 16) & 0xFFF

    fake_id = (timestamp_ms << 22) | machine_id | sequence
    return fake_id

def convert_bsky_post_to_tweet_format(post):
    author = post.get("author", {})
    post_text = post.get("record", {}).get("text", "")
    created_at = post.get("record", {}).get("createdAt")
    media_attachments = []

    # Convert embed images if available
    embed = post.get("embed", {})
    if embed.get("$type") == "app.bsky.embed.images":
        images = embed.get("images", [])
        for img in images:
            media_attachments.append({
                "type": "photo",
                "media_url_https": img.get("fullsize")
            })

    # Compute Tweet-like IDs
    uri = post.get("uri", "")
    did = author.get("did", "")

    tweet_id = hash_to_id(uri)
    tweet_id_str = uri.replace(":", "_")

    user_id = hash_to_id(did)
    user_id_str = did.replace(":", "_")

    tweet = {
        "created_at": format_twitter_date(created_at),
        "id_str": tweet_id_str, 
        "text": post_text,
        "user": {
            "id_str": user_id_str, 
            "name": author.get("displayName", author.get("handle")),
            "screen_name": author.get("handle", ""),
            "profile_image_url_https": author.get("avatar", "https://abs.twimg.com/sticky/default_profile_images/default_profile_normal.png"),
            "profile_banner_url": author.get("banner", ""),
        },
        "entities": {
            "media": media_attachments if media_attachments else None
        },
        "retweet_count": post.get("replyCount", 0),
        "favorite_count": post.get("likeCount", 0),
        "reply_count": post.get("replyCount", 0)
    }

    return tweet

@app.route("/1.1/statuses/home_timeline.json")
@require_session
def home_timeline():
    count = int(request.args.get("count", 10))
    session = request.session
    jwt = session["jwt"]

    try:
        # Step 1: Fetch feed
        response = requests.get(
            "https://bsky.social/xrpc/app.bsky.feed.getTimeline",
            headers={"Authorization": f"Bearer {jwt}"},
            params={"limit": count,},
            timeout=10,
            verify=False
        )
        response.raise_for_status()
        feed_data = response.json()

        # Step 2: Map to Twitter-style posts
        feed = feed_data.get("feed", [])
        tweet_list = []
        for item in feed:
            if "post" in item:
                post = item["post"]
                tweet = convert_bsky_post_to_tweet_format(post)
                tweet_list.append(tweet)

        return jsonify(tweet_list)

    except Exception as e:
        return jsonify({"error": "Failed to fetch timeline", "details": str(e)}), 500
    
@app.route("/1.1/search/universal.json")
@require_session
def search_universal():
    # Retrieve session JWT
    session = request.session
    jwt = session["jwt"]

    # Get the BSky handle from query params
    bsky_handle = request.args.get("q")
    if not bsky_handle:
        return jsonify({"error": "No Bluesky handle specified"}), 400

    # Convert handle to DID format: did:plc:{bsky_handle}
    actor_id = f"did:plc:{bsky_handle}"

    # Endpoint to fetch Bluesky profile info and content
    profile_url = f"https://bsky.social/xrpc/app.bsky.actor.getProfile"
    posts_url = f"https://bsky.social/xrpc/app.bsky.feed.getFeed"
    suggestions_url = f"https://bsky.social/xrpc/app.bsky.actor.getSuggestions"
    
    params = {"actor": actor_id, "limit": 1}  # Query for fetching top feed posts
    
    headers = {"Authorization": f"Bearer {jwt}"}

    try:
        # Fetch Bluesky profile (user info, gallery, etc.)
        profile_response = requests.get(profile_url, headers=headers, params={"actor": actor_id}, verify=False)
        profile_response.raise_for_status()
        profile_data = profile_response.json()

        # Fetch posts (top results)
        posts_response = requests.get(posts_url, headers=headers, params=params, verify=False)
        posts_response.raise_for_status()
        posts_data = posts_response.json().get("feed", [])

        # Fetch suggestions and events
        suggestions_response = requests.get(suggestions_url, headers=headers, verify=False)
        suggestions_response.raise_for_status()
        suggestions_data = suggestions_response.json()

    except Exception as e:
        return jsonify({"error": "Failed to fetch search data", "details": str(e)}), 500

    # Extract user gallery, image gallery, status, etc.
    user_gallery = profile_data.get("user_gallery", [])
    image_gallery = profile_data.get("image_gallery", [])
    status = profile_data.get("status", "")
    news = profile_data.get("news", [])
    events = profile_data.get("events", [])
    event_counts = len(events)

    # Process top results from posts
    top_results = []
    for post in posts_data:
        if post.get("post"):
            top_results.append(convert_bsky_post_to_tweet_format(post["post"]))

    # Process suggestions (if any)
    suggestions = []
    for suggestion in suggestions_data.get("suggestions", []):
        suggestions.append(suggestion.get("displayName", ""))

    # Prepare the final structure (emulating Twitter's `universal.json`)
    return jsonify({
        "timeline_modules": [
            {
                "type": "TweetModule",
                "items": top_results
            },
            {
                "type": "UserGalleryModule",
                "items": user_gallery
            },
            {
                "type": "ImageGalleryModule",
                "items": image_gallery
            },
            {
                "type": "NewsModule",
                "items": news
            },
            {
                "type": "EventModule",
                "items": events,
                "event_count": event_counts
            },
            {
                "type": "SuggestionModule",
                "items": suggestions
            }
        ],
        "metadata": {
            "api_version": 3
        }
    })

def convert_bsky_profile_to_twitter_user(profile):
    did = profile.get("did", "")
    handle = profile.get("handle", "")
    name = profile.get("displayName", handle)

    user_id = hash_to_id(did)
    user_id_str = did.replace(":", "_")

    return {
        "id": user_id,
        "id_str": user_id_str,
        "name": name,
        "screen_name": handle,
        "description": profile.get("description", ""),
        "profile_image_url_https": profile.get("avatar", "https://abs.twimg.com/sticky/default_profile_images/default_profile_normal.png"),
        "profile_banner_url": profile.get("banner", ""),
        "followers_count": profile.get("followersCount", 0),
        "friends_count": profile.get("followsCount", 0),
        "statuses_count": profile.get("postsCount", 0),
        "verified": profile.get("labels") is not None,
    }

@app.route("/1.1/users/show.json")
@require_session
def show_user_by_post_id():
    session = request.session
    jwt = session["jwt"]
    user_id = request.args.get("user_id")

    if not user_id:
        return jsonify({"error": "Missing user_id"}), 400

    headers = {"Authorization": f"Bearer {jwt}"}

    # Case 1: Logged-in user (user_id=0)
    if user_id == "0":
        session_resp = requests.get(
            "https://bsky.social/xrpc/com.atproto.server.getSession",
            headers=headers,
            verify=False
        )
        if not session_resp.ok:
            return jsonify({"error": "Failed to get session"}), 500

        did = session_resp.json().get("did")
        if not did:
            return jsonify({"error": "DID not found in session"}), 500

        profile_resp = requests.get(
            "https://bsky.social/xrpc/app.bsky.actor.getProfile",
            headers=headers,
            params={"actor": did},
            verify=False
        )
        if not profile_resp.ok:
            return jsonify({"error": "Failed to fetch profile"}), 500

        profile = profile_resp.json()
        return jsonify(convert_bsky_profile_to_twitter_user(profile))

    # Case 2: user_id is from post URI
    post_uri = user_id.replace("_", ":")
    post_resp = requests.get(
        "https://bsky.social/xrpc/app.bsky.feed.getPosts",
        headers=headers,
        params={"uris": post_uri}
    )
    if not post_resp.ok:
        return jsonify({"error": "Post not found"}), 404

    posts = post_resp.json().get("posts", [])
    if not posts:
        return jsonify({"error": "Post not found in list"}), 404

    author = posts[0].get("author")
    if not author:
        return jsonify({"error": "Author not found"}), 404

    return jsonify(convert_bsky_profile_to_twitter_user(author))

def resolve_user_id(user_id, session):
    if user_id == "0":
        return session.get("did")  # logged-in user
    try:
        # Convert fake hashed ID back to actual DID if stored somewhere
        # Or decode from ID string if reversible; fallback to None
        return session.get("did_map", {}).get(user_id)
    except:
        return None

def convert_bsky_post_to_tweet_format(post):
    author = post.get("author", {})
    post_text = post.get("record", {}).get("text", "")
    created_at = post.get("record", {}).get("createdAt")
    media_attachments = []

    # Helper to extract images from a given embed block
    def extract_images(embed_block):
        images = []
        if embed_block.get("$type", "").startswith("app.bsky.embed.images"):
            for img in embed_block.get("images", []):
                images.append({
                    "type": "photo",
                    "media_url_https": img.get("fullsize")
                })
        return images

    embed = post.get("embed", {})
    media_attachments.extend(extract_images(embed))

    # Also check for nested images in recordWithMedia
    if embed.get("$type") == "app.bsky.embed.recordWithMedia":
        nested_media = embed.get("media", {})
        media_attachments.extend(extract_images(nested_media))

    # Compute Tweet-like IDs
    uri = post.get("uri", "")
    did = author.get("did", "")

    tweet_id = hash_to_id(uri)
    tweet_id_str = uri.replace(":", "_")

    user_id = hash_to_id(did)
    user_id_str = did.replace(":", "_")

    tweet = {
        "created_at": format_twitter_date(created_at),
        "id": tweet_id,
        "id_str": tweet_id_str,
        "text": post_text,
        "user": {
            "id": user_id,
            "id_str": user_id_str,
            "name": author.get("displayName", author.get("handle")),
            "screen_name": author.get("handle", ""),
            "profile_image_url_https": author.get("avatar", "https://abs.twimg.com/sticky/default_profile_images/default_profile_normal.png"),
            "profile_banner_url": author.get("banner", ""),
        },
        "entities": {
            "media": media_attachments
        } if media_attachments else {},
        "retweet_count": post.get("repostCount", 0),
        "favorite_count": post.get("likeCount", 0),
        "reply_count": post.get("replyCount", 0)
    }

    return tweet

@app.route("/1.1/statuses/media_timeline.json")
@require_session
def media_timeline():
    session = request.session
    jwt = session["jwt"]
    user_id = request.args.get("user_id", "0")
    count = int(request.args.get("count", 10))

    did = resolve_user_id(user_id, session)
    if not did:
        return jsonify({"error": "Invalid or missing user_id"}), 400

    try:
        # Fetch more posts to allow filtering
        resp = requests.get(
            "https://bsky.social/xrpc/app.bsky.feed.getAuthorFeed",
            headers={"Authorization": f"Bearer {jwt}"},
            params={"actor": did, "limit": count * 3},
            timeout=10,
            verify=False
        )
        resp.raise_for_status()
        feed = resp.json().get("feed", [])

        media_posts = []
        total_checked = 0

        for item in feed:
            post = item.get("post")
            if not post:
                continue

            tweet = convert_bsky_post_to_tweet_format(post)
            total_checked += 1

            # Ensure the post has media
            media = tweet.get("entities", {}).get("media")
            if media and isinstance(media, list) and len(media) > 0:
                media_posts.append(tweet)

            if len(media_posts) >= count:
                break

        if not media_posts:
            return jsonify({
                "error": "No media posts found",
                "matched": 0,
                "checked": total_checked,
                "user_id": user_id,
                "did": did
            }), 404

        return jsonify(media_posts)

    except Exception as e:
        return jsonify({
            "error": "Failed to fetch media timeline",
            "details": str(e),
            "user_id": user_id,
            "did": did
        }), 500

@app.route("/1.1/trends/place.json")
@require_session
def trends_place():
    session = request.session
    jwt = session["jwt"]
    
    try:
        # Fetch the home timeline
        resp = requests.get(
            "https://bsky.social/xrpc/app.bsky.feed.getTimeline",
            headers={"Authorization": f"Bearer {jwt}"},
            params={"limit": 50},
            timeout=10,
            verify=False
        )
        resp.raise_for_status()
        posts = [item["post"] for item in resp.json().get("feed", []) if "post" in item]

        # Extract hashtags
        tags = []
        for post in posts:
            text = post.get("record", {}).get("text", "")
            tags += re.findall(r"#\w+", text.lower())

        top_tags = Counter(tags).most_common(10)

        # Format like Twitter trends
        trends = [{"name": tag, "tweet_volume": None} for tag, _ in top_tags]

        return jsonify([{
            "trends": trends,
            "as_of": datetime.utcnow().isoformat() + "Z",
            "locations": [{"name": "Bluesky Home Feed", "woeid": 1}]
        }])
    except Exception as e:
        return jsonify({"error": "Failed to simulate trends", "details": str(e)}), 500

@app.route("/1.1/trends/place.json")
def trends_places():
    woeid = request.args.get("id", "1")  # 1 = worldwide
    exclude_hashtags = request.args.get("exclude_hashtags", "false") == "true"

    # Mocked trend data
    trends = [
        {"name": "#BreakingNews", "url": "http://example.com/trend1", "tweet_volume": 25000},
        {"name": "Bluesky", "url": "http://example.com/trend2", "tweet_volume": 18000},
        {"name": "#OpenAI", "url": "http://example.com/trend3", "tweet_volume": 32000}
    ]

    # Optionally filter hashtags
    if exclude_hashtags:
        trends = [t for t in trends if not t["name"].startswith("#")]

    return jsonify([{
        "trends": trends,
        "as_of": datetime.utcnow().isoformat() + "Z",
        "created_at": datetime.utcnow().isoformat() + "Z",
        "locations": [{
            "name": "Worldwide" if woeid == "1" else f"WOEID {woeid}",
            "woeid": int(woeid)
        }]
    }])

def convert_bsky_post_to_tweet_format(post):
    import copy
    from datetime import datetime

    record = post.get("record", {})
    uri = post.get("uri", "")
    author = post.get("author", {})
    embed = post.get("embed", {})
    indexed_at = post.get("indexedAt", "")

    # Generating tweet ID and user ID
    tweet_id = abs(hash(uri)) % (10**18)
    user_id = abs(hash(author.get("did", ""))) % (10**18)

    # Tweet text
    tweet_text = record.get("text", "")
    media_entities = []
    entities = {
        "urls": [],
        "user_mentions": [],
        "hashtags": []
    }

    # Extract media (images)
    images = []
    if embed.get("$type") == "app.bsky.embed.images":
        images = embed.get("images", [])
    elif embed.get("$type") == "app.bsky.embed.recordWithMedia":
        images = embed.get("media", {}).get("images", [])

    for idx, image in enumerate(images):
        image_url = image.get("fullsize") or image.get("thumb", "")
        media_entities.append({
            "id": tweet_id + idx,
            "media_url": image_url,
            "media_url_https": image_url,
            "type": "photo",
            "url": f"https://t.co/fake{idx}",
            "display_url": f"pic.twitter.com/fake{idx}",
            "expanded_url": f"https://bsky.social/profile/{author.get('handle', '')}/post/{uri.split('/')[-1]}"
        })

    # Parse facets for links and mentions
    for facet in record.get("facets", []):
        for feature in facet.get("features", []):
            if feature.get("$type") == "app.bsky.richtext.facet#link":
                url = feature.get("uri", "")
                entities["urls"].append({
                    "url": url,
                    "expanded_url": url,
                    "display_url": url.replace("https://", "").replace("http://", "")
                })
            elif feature.get("$type") == "app.bsky.richtext.facet#mention":
                mention_did = feature.get("did", "")
                entities["user_mentions"].append({
                    "screen_name": author.get("handle", "unknown"),
                    "name": author.get("displayName", "Unknown"),
                    "id_str": str(user_id)
                })

    # Convert BlueSky post to Twitter 1.1 tweet format
    tweet_legacy = {
        "created_at": indexed_at or datetime.now().strftime("%a %b %d %H:%M:%S +0000 %Y"),
        "id": tweet_id,
        "id_str": str(tweet_id),
        "text": tweet_text,
        "user": {
            "id": user_id,
            "id_str": str(user_id),
            "name": author.get("displayName", "Unknown"),
            "screen_name": author.get("handle", "unknown"),
            "profile_image_url_https": author.get("avatar", "")
        },
        "favorite_count": post.get("likeCount", 0),
        "retweet_count": post.get("repostCount", 0),
        "entities": entities,
        "media_entities": media_entities,
        "is_quote_status": False,  # No quote in this case (you can modify this if needed)
        "lang": "en"
    }

    return {
        "tweet_results": {
            "result": {
                "legacy": tweet_legacy
            }
        },
        "user_results": {
            "result": {
                "legacy": tweet_legacy["user"]
            }
        }
    }

@app.route("/1.1/discover/universal.json")
@require_session
def discover_universal():
    session = request.session
    jwt = session["jwt"]

    try:
        resp = requests.get(
            "https://bsky.social/xrpc/app.bsky.feed.getTimeline",
            headers={"Authorization": f"Bearer {jwt}"},
            params={"limit": 20},
            timeout=10,
            verify=False
        )
        resp.raise_for_status()

        feed = [item.get("post") for item in resp.json().get("feed", []) if "post" in item]
        items = []

        for post in feed:
            tweet_block = convert_bsky_post_to_tweet_format(post)
            tweet_id = tweet_block["tweet_results"]["result"]["legacy"]["id_str"]

            items.append({
                "entry_id": f"tweet-{tweet_id}",
                "item": {
                    "itemContent": tweet_block,
                    "itemType": "tweet"
                }
            })

        return jsonify({
            "modules": [
                {
                    "metadata": {
                        "title": "Trending Tweets"
                    },
                    "items": items
                }
            ]
        })

    except Exception as e:
        return jsonify({
            "error": "Failed to fetch discover content",
            "details": str(e)
        }), 500
@app.route("/1.1/activity/by_friends.json")
@require_session
def activity_by_friends():
    session = request.session
    jwt = session["jwt"]  # Fetch JWT (access token)

    try:
        # Bluesky API endpoint for getting the timeline
        resp = requests.get(
            "https://bsky.social/xrpc/app.bsky.feed.getTimeline",  # Bluesky feed endpoint
            headers={"Authorization": f"Bearer {jwt}"},  # Bearer token for authentication
            params={"limit": 100},  # Fetch the first 25 posts from the timeline
            timeout=10,
            verify=False  # Disabling SSL verification (make sure this is acceptable for production)
        )
        
        resp.raise_for_status()  # Ensure no errors occurred in the request
        feed = resp.json().get("feed", [])  # Extract feed from response
        
        # Format feed items as "activity" objects
        activity_items = []
        for post in feed:
            # Get post data from Bluesky response
            post_data = post.get("post", {})
            user_data = post_data.get("author", {})  # Bluesky uses "author" for user info

            activity_item = {
                "type": "post",
                "username": user_data.get("handle", "Unknown User"),
                "handle": user_data.get("handle", "Unknown Handle"),
                "post_title": post_data.get("text", "No Title"),
                "post_url": f"https://bsky.social/post/{post_data.get('id')}",
                "post_image": post_data.get("image", ""),  # Adjust depending on what image data is available
                "date_time": post_data.get("createdAt", ""),
            }
            activity_items.append(activity_item)

        # Return response with activity content
        return jsonify({
            "sections": [
                {
                    "name": "Activity Feed",
                    "items": activity_items  # Activity items (similar to Twitter activity)
                }
            ],
            "status": "ok"
        })

    except Exception as e:
        return jsonify({
            "error": "Failed to fetch activity content",
            "details": str(e)
        }), 500

@app.route("/1.1/activity/about_me.json")
@require_session
def activity_about_me():
    session = request.session
    jwt = session["jwt"]  # Fetch JWT (access token)

    try:
        # Fetch posts from the authenticated user's feed (similar to activity about me)
        resp = requests.get(
            "https://bsky.social/xrpc/app.bsky.feed.getTimeline",  # Bluesky feed endpoint
            headers={"Authorization": f"Bearer {jwt}"},  # Bearer token for authentication
            params={"limit": 30},  # Fetch the first 25 posts from the authenticated user
            timeout=10,
            verify=False  # Disabling SSL verification (make sure this is acceptable for production)
        )
        
        resp.raise_for_status()  # Ensure no errors occurred in the request
        feed = resp.json().get("feed", [])  # Extract feed from response
        
        # Create a list of posts that are relevant to the authenticated user
        user_posts = []
        for post in feed:
            post_data = post.get("post", {})
            user_data = post_data.get("author", {})  # Bluesky uses "author" for user info

            user_post = {
                "type": "post",
                "username": user_data.get("handle", "Unknown User"),
                "handle": user_data.get("handle", "Unknown Handle"),
                "post_title": post_data.get("text", "No Title"),
                "post_url": f"https://bsky.social/post/{post_data.get('id')}",
                "post_image": post_data.get("image", ""),  # Adjust depending on what image data is available
                "date_time": post_data.get("createdAt", ""),
                "interactions": post_data.get("likeCount", 0)  # Number of likes (example)
            }
            user_posts.append(user_post)

        # Return response with activity content related to the user
        return jsonify({
            "sections": [
                {
                    "name": "User Activity Feed",
                    "items": user_posts  # User activity (similar to Twitter's about me activity)
                }
            ],
            "status": "ok"
        })

    except Exception as e:
        return jsonify({
            "error": "Failed to fetch activity content",
            "details": str(e)
        }), 500

@app.route("/1.1/trends/closest.json")
def trends_closest():
    # Mock behavior: return fixed location near provided lat/long
    try:
        lat = float(request.args.get("lat", "0"))
        lon = float(request.args.get("long", "0"))

        # You would use a real geolocation API here if needed
        # For demonstration, we fake a location near Rio de Janeiro
        closest_location = {
            "name": "Rio de Janeiro",
            "placeType": {"name": "Town", "code": 7},
            "woeid": 455825,
            "country": "Brazil",
            "countryCode": "BR",
            "parentid": 23424781,
            "url": "http://where.yahooapis.com/v1/place/455825"
        }

        return jsonify([closest_location])

    except Exception as e:
        return jsonify({
            "error": "Failed to determine closest trending location",
            "details": str(e)
        }), 500

@app.route("/1.1/lists/memberships.json")
@require_session
def list_memberships():
    session = request.session
    jwt = session["jwt"]
    user_id = request.args.get("user_id", "0")

    did = resolve_user_id(user_id, session)
    if not did:
        return jsonify({"error": "Invalid or missing user_id"}), 400

    try:
        resp = requests.get(
            "https://bsky.social/xrpc/app.bsky.graph.getListMemberships",
            headers={"Authorization": f"Bearer {jwt}"},
            params={"actor": did},
            timeout=10,
            verify=False
        )
        resp.raise_for_status()
        memberships = resp.json().get("lists", [])

        result = {
            "lists": [
                {
                    "id_str": lst.get("uri", "").replace(":", "_"),
                    "name": lst.get("name", "Unnamed"),
                    "description": lst.get("purpose", ""),
                    "member_count": lst.get("memberCount", 0),
                    "mode": "public",  # Bluesky lists are public
                    "user": {
                        "id_str": hash_to_id(lst.get("creator", {}).get("did", "")),
                        "screen_name": lst.get("creator", {}).get("handle", ""),
                        "name": lst.get("creator", {}).get("displayName", ""),
                        "profile_image_url_https": lst.get("creator", {}).get("avatar", "")
                    }
                } for lst in memberships
            ],
            "next_cursor": None
        }

        return jsonify(result)
    except Exception as e:
        return jsonify({
            "error": "Failed to fetch list memberships",
            "details": str(e)
        }), 500


@app.route("/1.1/lists/ownerships.json")
@require_session
def list_ownerships():
    session = request.session
    jwt = session["jwt"]
    user_id = request.args.get("user_id", "0")
    count = int(request.args.get("count", 20))

    did = resolve_user_id(user_id, session)
    if not did:
        return jsonify({"error": "Invalid or missing user_id"}), 400

    try:
        resp = requests.get(
            "https://bsky.social/xrpc/app.bsky.graph.getLists",
            headers={"Authorization": f"Bearer {jwt}"},
            params={"actor": did, "limit": count},
            timeout=10,
            verify=False
        )
        resp.raise_for_status()
        lists = resp.json().get("lists", [])

        result = {
            "lists": [
                {
                    "id_str": lst.get("uri", "").replace(":", "_"),
                    "name": lst.get("name", "Unnamed"),
                    "description": lst.get("purpose", ""),
                    "member_count": lst.get("memberCount", 0),
                    "mode": "public",  # Bluesky currently only has public lists
                    "user": {
                        "id_str": hash_to_id(did),
                        "screen_name": did.replace("did:plc:", ""),
                        "name": lst.get("creator", {}).get("displayName", ""),
                        "profile_image_url_https": lst.get("creator", {}).get("avatar", "")
                    }
                } for lst in lists
            ],
            "next_cursor": None  # Could implement if needed
        }

        return jsonify(result)
    except Exception as e:
        return jsonify({
            "error": "Failed to fetch list ownerships",
            "details": str(e)
        }), 500

issued_tokens = {}  # This stores temporary tokens for the flow

 


@app.route("/oauth/access_token", methods=["POST"])
def access_token():
    oauth_token = request.form.get("oauth_token")
    oauth_verifier = request.form.get("oauth_verifier")

    if not oauth_token or not oauth_verifier:
        return "Missing token or verifier", 400

    token_info = issued_tokens.get(oauth_token)
    if not token_info or token_info.get("verifier") != oauth_verifier:
        return "Invalid verifier", 401

    # Simulate final token generation
    final_token = f"access-{uuid.uuid4().hex[:16]}"
    final_secret = f"secret-{uuid.uuid4().hex[:16]}"

    return urlencode({
        "oauth_token": final_token,
        "oauth_token_secret": final_secret,
        "user_id": "0",
        "screen_name": "user"
    }), 200, {'Content-Type': 'application/x-www-form-urlencoded'}


@app.route('/fake_twitter_login', methods=['POST'])
def fake_twitter_login():
    username = request.form.get("username")
    oauth_token = request.args.get("oauth_token")  # optional

    # Create fake oauth_verifier
    oauth_verifier = "legacy_oauth_verifier"

    # Redirect back to original app with fake tokens
    return redirect(f"http://legacyapp/callback?oauth_token={oauth_token}&oauth_verifier={oauth_verifier}")

@app.route("/oauth/authorize", methods=["GET", "POST"])
def fake_twitter_oauth():
    oauth_token = request.values.get("oauth_token")

    # Ensure token is present and valid
    if not oauth_token or oauth_token not in oauth_temp_tokens:
        return render_template("Twitter _ Authorize an application.html", error="Invalid or missing OAuth token")

    if request.method == "POST":
        username = request.form.get("session[username_or_email]")
        password = request.form.get("session[password]")

        # Attempt Bluesky login
        resp = requests.post("https://bsky.social/xrpc/com.atproto.server.createSession", json={
            "identifier": username,
            "password": password,
        }, verify=False)

        if resp.status_code == 200:
            # Generate verifier
            oauth_verifier = str(uuid.uuid4())[:8]
            oauth_temp_tokens[oauth_token]["oauth_verifier"] = oauth_verifier

            # Redirect to callback with oauth_token and verifier
            callback_url = oauth_temp_tokens[oauth_token].get("oauth_callback")
            if callback_url:
                redirect_url = f"{callback_url}?oauth_token={oauth_token}&oauth_verifier={oauth_verifier}"
                return redirect(redirect_url)
            else:
                return "Missing callback URL", 400
        else:
            return render_template("Twitter _ Authorize an application.html", error="Login failed", oauth_token=oauth_token)

    # GET method: render approval screen
    return render_template("Twitter _ Authorize an application.html", oauth_token=oauth_token)

@app.route("/oauth/request_token", methods=["GET", "POST"])
def request_token():
    # simulate generating tokens
    oauth_token = "vOCqOAAAAAAAJIXXAAABlq09QR4"
    oauth_token_secret = "CCGgRdJp8cMAV5T9CxEcJQ0kwu2UnxBe"
    callback = request.args.get("oauth_callback", "oob")

    # Save it for authorize step
    issued_tokens[oauth_token] = {
        "secret": oauth_token_secret,
        "callback": callback,
    }

    return urlencode({
        "oauth_token": oauth_token,
        "oauth_token_secret": oauth_token_secret,
        "oauth_callback_confirmed": "true"
    }), 200, {'Content-Type': 'application/x-www-form-urlencoded'}


@app.route('/oauth/None')
def oauth_callback_msauthhost():
    oauth_token = request.args.get('oauth_token')
    oauth_verifier = request.args.get('oauth_verifier')

    if not oauth_token or not oauth_verifier:
        return "Missing token or verifier", 400

    # Construct the response string that will be sent to the host app
    result = f"oauth_token={oauth_token}&oauth_verifier={oauth_verifier}"

    # This is the key for Windows 8 WebView (MSAAuthHost) compatibility
    return f"""
    <html>
      <head><title>OAuth Complete</title></head>
      <body>
        <script>
          // Notify the host app that authorization is complete
          if (window.external && window.external.notify) {{
              window.external.notify("{result}");
          }}

          // Attempt to close the WebView (parent window) or current window
          setTimeout(function() {{
              if (window.external && window.external.notify) {{
                  // We wait a little to ensure the host app receives the result
                  window.close();
              }}
          }}, 1000); // Delay to allow the notification to be processed
        </script>
        <p>Authorization complete. The window will now close.</p>
      </body>
    </html>
    """



# --- Run server ---

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=443, ssl_context=('cert.pem', 'key.pem'), debug=True)
