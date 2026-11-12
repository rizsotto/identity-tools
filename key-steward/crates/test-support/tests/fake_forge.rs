//! The fake forges behave like the documented APIs: auth, paged lists
//! with `link` headers, add, delete, error codes and faults.

use serde_json::{Value, json};
use test_support::{FakeForge, Fault, FaultOn, Flavour, KeyList};

const NEW_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAMl5AYo+0XU3NureorqVJl9BQCzJ/7O6oQuY+n0zaV+ new@test";
const NEW_BLOB: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAMl5AYo+0XU3NureorqVJl9BQCzJ/7O6oQuY+n0zaV+";

struct Client {
    http: reqwest::Client,
    api: String,
    auth: (&'static str, String),
}

impl Client {
    fn new(forge: &FakeForge) -> Client {
        let t = forge.token();
        let auth = match forge.flavour() {
            Flavour::GitHub => ("authorization", format!("Bearer {t}")),
            Flavour::GitLab => ("private-token", t),
            Flavour::Forgejo => ("authorization", format!("token {t}")),
        };
        Client {
            http: reqwest::Client::new(),
            api: forge.api_url(),
            auth,
        }
    }

    async fn send(&self, rb: reqwest::RequestBuilder) -> (u16, reqwest::header::HeaderMap, Value) {
        let resp = rb.header(self.auth.0, &self.auth.1).send().await.unwrap();
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        let body = resp.bytes().await.unwrap();
        let body = serde_json::from_slice(&body).unwrap_or(Value::Null);
        (status, headers, body)
    }

    async fn get(&self, path: &str) -> (u16, reqwest::header::HeaderMap, Value) {
        self.send(self.http.get(format!("{}{path}", self.api)))
            .await
    }

    async fn post(&self, path: &str, body: Value) -> (u16, Value) {
        let rb = self
            .http
            .post(format!("{}{path}", self.api))
            .header("content-type", "application/json")
            .body(body.to_string());
        let (s, _, b) = self.send(rb).await;
        (s, b)
    }

    async fn delete(&self, path: &str) -> u16 {
        self.send(self.http.delete(format!("{}{path}", self.api)))
            .await
            .0
    }

    /// Follows `link: rel="next"` and returns every item.
    async fn list(&self, path: &str) -> Vec<Value> {
        let mut url = format!("{}{path}", self.api);
        let mut items = Vec::new();
        loop {
            let (s, h, body) = self.send(self.http.get(&url)).await;
            assert_eq!(s, 200, "{url}: {body}");
            items.extend(body.as_array().unwrap().clone());
            let next = h.get("link").and_then(|l| {
                l.to_str().unwrap().split(", ").find_map(|part| {
                    part.strip_suffix("; rel=\"next\"")
                        .map(|u| u.trim_matches(['<', '>']).to_string())
                })
            });
            match next {
                Some(n) => url = n,
                None => return items,
            }
        }
    }
}

fn keys_of(items: &[Value]) -> Vec<&str> {
    items.iter().map(|k| k["key"].as_str().unwrap()).collect()
}

/// The status a rejected key gets: GitLab 400, the others 422.
fn rejected(f: Flavour) -> u16 {
    if f == Flavour::GitLab { 400 } else { 422 }
}

async fn add_list_delete(forge: FakeForge, list_path: &str, seeded: usize) {
    let f = forge.flavour();
    let c = Client::new(&forge);
    let page = if f == Flavour::Forgejo {
        "limit=50"
    } else {
        "per_page=100"
    };
    let list = format!("{list_path}?{page}");

    // No token, or a wrong one: 401.
    let bare = reqwest::get(format!("{}/user", forge.api_url()))
        .await
        .unwrap();
    assert_eq!(bare.status().as_u16(), 401);
    let (s, _, user) = c.get("/user").await;
    assert_eq!(s, 200);
    let field = if f == Flavour::GitLab {
        "username"
    } else {
        "login"
    };
    assert_eq!(user[field], "testuser");

    // max_per_page(2) makes the seeds span pages.
    let (_, h, first) = c.get(&list).await;
    assert_eq!(first.as_array().unwrap().len(), 2);
    let link = h.get("link").unwrap().to_str().unwrap();
    assert!(
        link.contains("rel=\"next\"") && link.contains("page=2"),
        "{link}"
    );
    assert!(link.starts_with(&format!("<{}", forge.api_url())), "{link}");
    assert_eq!(c.list(&list).await.len(), seeded);

    // Add.
    let mut body = json!({ "title": "new", "key": NEW_KEY });
    if f == Flavour::GitLab {
        body["usage_type"] = json!("signing");
    }
    let (s, made) = c.post(list_path, body.clone()).await;
    assert_eq!(s, 201, "{made}");
    assert_eq!(made["key"], NEW_BLOB);
    assert_eq!(made["title"], "new");
    let id = made["id"].as_u64().unwrap();
    let all = c.list(&list).await;
    assert_eq!(all.len(), seeded + 1);
    assert!(keys_of(&all).contains(&NEW_BLOB));
    match f {
        Flavour::GitLab => assert_eq!(made["usage_type"], "signing"),
        Flavour::Forgejo => assert_eq!(
            made["fingerprint"],
            "SHA256:qdGYTRZqqtsi/yfdc1B/aEJM1mqIrAWmI28G0eEe8Xo"
        ),
        Flavour::GitHub => {}
    }

    // The same key again, a missing field, a bad key.
    assert_eq!(c.post(list_path, body).await.0, rejected(f));
    let missing = if f == Flavour::GitHub {
        json!({ "title": "x" })
    } else {
        json!({ "key": NEW_KEY })
    };
    assert_eq!(c.post(list_path, missing).await.0, rejected(f));
    let bad = json!({ "title": "x", "key": "ssh-ed25519 AAAAnotakey" });
    assert_eq!(c.post(list_path, bad).await.0, rejected(f));

    // Delete.
    assert_eq!(c.delete(&format!("{list_path}/{id}")).await, 204);
    assert_eq!(c.delete(&format!("{list_path}/{id}")).await, 404);
    assert_eq!(c.list(&list).await.len(), seeded);
    assert!(forge.keys().iter().all(|k| k.id != id));

    // Every request is recorded, in order, without the token.
    let reqs = forge.requests();
    let posts: Vec<_> = reqs.iter().filter(|r| r.method == "POST").collect();
    assert_eq!(posts.len(), 4);
    assert_eq!(posts[0].status, Some(201));
    assert_eq!(posts[0].body.as_ref().unwrap()["key"], NEW_KEY);
    let deletes: Vec<_> = reqs.iter().filter(|r| r.method == "DELETE").collect();
    assert_eq!(
        deletes.iter().map(|r| r.status).collect::<Vec<_>>(),
        [Some(204), Some(404)]
    );
    assert!(!format!("{reqs:?}").contains(&forge.token()));
}

#[tokio::test]
async fn fake_forge_add_list_delete_github() {
    let forge = FakeForge::builder(Flavour::GitHub)
        .max_per_page(2)
        .start()
        .await;
    add_list_delete(forge, "/user/keys", 3).await;

    // Signing keys are a separate list: the same key can be in both.
    let forge = FakeForge::start(Flavour::GitHub).await;
    let c = Client::new(&forge);
    let body = json!({ "title": "s", "key": NEW_KEY });
    assert_eq!(c.post("/user/keys", body.clone()).await.0, 201);
    let (s, made) = c.post("/user/ssh_signing_keys", body).await;
    assert_eq!(s, 201);
    let signing = c.list("/user/ssh_signing_keys").await;
    assert_eq!(signing.len(), 2);
    assert!(keys_of(&signing).contains(&NEW_BLOB));
    let id = made["id"].as_u64().unwrap();
    assert_eq!(c.delete(&format!("/user/keys/{id}")).await, 404);
    assert_eq!(c.delete(&format!("/user/ssh_signing_keys/{id}")).await, 204);
    let left = forge.keys();
    assert_eq!(
        left.iter()
            .filter(|k| k.key == NEW_BLOB)
            .map(|k| k.list)
            .collect::<Vec<_>>(),
        [KeyList::Auth]
    );
}

#[tokio::test]
async fn fake_forge_add_list_delete_gitlab() {
    let forge = FakeForge::builder(Flavour::GitLab)
        .prefix("/gitlab")
        .max_per_page(2)
        .start()
        .await;
    assert!(forge.api_url().ends_with("/gitlab/api/v4"));
    let c = Client::new(&forge);
    let (_, h, _) = c.get("/user/keys?per_page=2").await;
    assert_eq!(h["x-next-page"], "2");
    assert_eq!(h["x-total"], "4");
    let (_, h, _) = c.get("/user/keys?per_page=2&page=2").await;
    assert_eq!(h["x-next-page"], "");
    add_list_delete(forge, "/user/keys", 4).await;

    // Without usage_type the key serves both.
    let forge = FakeForge::builder(Flavour::GitLab).empty().start().await;
    let c = Client::new(&forge);
    let (s, made) = c
        .post("/user/keys", json!({ "title": "t", "key": NEW_KEY }))
        .await;
    assert_eq!(s, 201);
    assert_eq!(made["usage_type"], "auth_and_signing");
    let bad = json!({ "title": "t", "key": NEW_KEY, "usage_type": "other" });
    assert_eq!(c.post("/user/keys", bad).await.0, 400);
}

#[tokio::test]
async fn fake_forge_add_list_delete_forgejo() {
    let forge = FakeForge::builder(Flavour::Forgejo)
        .max_per_page(2)
        .start()
        .await;
    let c = Client::new(&forge);
    let (_, h, _) = c.get("/user/keys").await;
    assert_eq!(h["x-total-count"], "3");
    add_list_delete(forge, "/user/keys", 3).await;
}

/// The fault applies the write, then answers 502 or closes the
/// connection. A retry then sees the key already there or already gone.
#[tokio::test]
async fn fake_forge_lost_response_applies() {
    for f in [Flavour::GitHub, Flavour::GitLab, Flavour::Forgejo] {
        let forge = FakeForge::builder(f).empty().start().await;
        let c = Client::new(&forge);
        let body = json!({ "title": "new", "key": NEW_KEY });

        // A GET does not take a write fault.
        forge.fail_next(FaultOn::Write, Fault::LoseResponse);
        assert_eq!(c.get("/user").await.0, 200);
        assert_eq!(c.post("/user/keys", body.clone()).await.0, 502);
        assert_eq!(forge.keys().len(), 1, "{f:?}");
        assert_eq!(c.post("/user/keys", body.clone()).await.0, rejected(f));
        let id = forge.keys()[0].id;

        forge.fail_next(FaultOn::Write, Fault::LoseResponse);
        assert_eq!(c.delete(&format!("/user/keys/{id}")).await, 502);
        assert!(forge.keys().is_empty());
        assert_eq!(c.delete(&format!("/user/keys/{id}")).await, 404);

        // 500 and 403 change nothing.
        forge.fail_next(FaultOn::Write, Fault::Status(500));
        forge.fail_next(FaultOn::Any, Fault::Status(403));
        assert_eq!(c.post("/user/keys", body.clone()).await.0, 500);
        let (s, _, err) = c.get("/user").await;
        assert_eq!(s, 403, "{err}");
        assert!(forge.keys().is_empty());

        // Closed connection, applied and not applied.
        forge.fail_next(FaultOn::Write, Fault::CloseConnection { apply: false });
        let url = format!("{}/user/keys", forge.api_url());
        let send = || {
            reqwest::Client::new()
                .post(&url)
                .header(c.auth.0, &c.auth.1)
                .header("content-type", "application/json")
                .body(body.to_string())
                .send()
        };
        assert!(send().await.is_err());
        assert!(forge.keys().is_empty());
        forge.fail_next(FaultOn::Write, Fault::CloseConnection { apply: true });
        assert!(send().await.is_err());
        assert_eq!(forge.keys().len(), 1);

        let statuses: Vec<_> = forge.requests().iter().map(|r| r.status).collect();
        assert_eq!(
            statuses,
            [
                Some(200),
                Some(502),
                Some(rejected(f)),
                Some(502),
                Some(404),
                Some(500),
                Some(403),
                None,
                None
            ],
            "{f:?}"
        );
    }
}
