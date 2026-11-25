# Credential Hygiene and Secret Leak Remediation Guide

**Status:** Developer guide
**Governing Issue:** [oss-slu/oss_cybersecurity#79](https://github.com/oss-slu/oss_cybersecurity/issues/79)
**Applies to:** every student developer, maintainer, and new contributor working in an OSS-SLU project repository
**Related risk:** R-01 (committed secrets) in the [Security Risk Register](../risk_assessment.md)

---

## Purpose

This is a practical guide for OSS-SLU developers on **preventing, managing, and remediating** committed secrets: API tokens, passwords, private keys, database credentials, and any other value that grants access to a system.

It is organized around the three moments when you can stop a leak:

| Moment | What you can still do | Go to |
|---|---|---|
| **Before you commit** | Keep secrets out of your files and out of git entirely | [Part 1](#part-1-proactive-credential-hygiene-before-you-commit) |
| **Before it is public** | GitHub Push Protection blocks your push; fix your local commits | [Part 2](#part-2-working-with-github-push-protection) |
| **After you push** | Revoke the secret first, then clean up history | [Part 3](#part-3-emergency-leak-remediation-runbook-if-a-secret-gets-pushed) |

> 🚨 **If you just pushed a secret, stop reading here and go straight to [Part 3, Step 1](#step-1-revoke-and-rotate-immediately).** Every minute counts.

[Part 4](#part-4-quick-reference--developer-cheat-sheet) is a one-page cheat sheet to bookmark for onboarding and pull request reviews.

---

## Core Concepts: The Anatomy of a Leaked Secret

### What counts as a secret?

Anything that would let someone else act as you, as your project, or as the organization:

- API keys and tokens (GitHub personal access tokens, cloud keys, Stripe, Postmark, Cloudflare, and so on)
- Passwords and database connection strings (`postgres://user:password@host/db`)
- Private keys (`id_rsa`, `*.pem`, `*.key`) and certificates' private halves
- Signing secrets (`JWT_SECRET`, session secrets)
- Service account files (`credentials.json`, `service-account.json`)
- Registry and deployment credentials (Harbor robot accounts, Kubernetes tokens)

If you are not sure whether something is a secret, treat it as one.

### Why commits are immutable

A git commit is a permanent snapshot of your files at that moment. Later commits do not change earlier ones; they only add new snapshots on top. That means none of these common "fixes" removes a secret:

| What people try | What it actually does |
|---|---|
| `git rm .env` | Removes the file from the **next** snapshot. The commit that added it still contains it. |
| `git commit -m "remove secret"` after editing the file | Adds a new snapshot without the secret. The old snapshot still has it, and the diff of your "remove secret" commit **shows the secret** in red. |
| Adding `.env` to `.gitignore` after committing it | `.gitignore` only affects files that are **not yet tracked**. It does nothing to a file that is already in history. |
| `git reset --hard HEAD~1` (before pushing) | Moves your branch back, but the old commit stays in your local **reflog** and object database until git cleans it up, usually weeks later. Safe only if you never pushed it. |

Here is what that looks like in a test repository. A fake key is committed, then "removed" all three ways:

```console
$ git log --oneline
2b264d9 ignore .env
a4a822c remove secret
05c0ef2 add config
7f43c57 init

$ git ls-files              # the current snapshot looks clean...
.gitignore
app.py

$ git grep -n "sk_test_FAKE" $(git rev-list --all)   # ...but history is not
05c0ef2db606a96408a543cc663909feba25774c:.env:1:API_KEY=sk_test_FAKE_1234567890
```

Even after `git reset --hard` rewinds the branch past all three commits, the reflog still points at them, and `git show 05c0ef2:.env` still prints the key.

Once a commit is **pushed to GitHub**, it also exists in places you cannot clean yourself: every clone made by teammates or bots, every fork, pull request references, and GitHub's cached views of the commit [1]. This is why the first step after a leak is always **revoking** the secret, not deleting it (Part 3).

### The speed of public compromise

Most OSS-SLU repositories are public. Pushing to a public repository, on **any** branch, including a feature branch or a fork, publishes your commit to the world immediately.

Attackers run automated bots that watch new public commits and harvest credentials as they appear. In one documented campaign, attackers found AWS keys pushed to public GitHub repositories and were using them **within five minutes** of exposure, to run cryptocurrency miners billed to the key's owner [2]. Researchers studying public GitHub have found thousands of new secrets leaked every day [3].

Code review does not protect you here: the pull request is opened **after** the push, and by then the secret is already public.

> ⚠️ **Rule of thumb:** the moment a secret reaches a public GitHub repository, assume it has been copied. Deleting the commit, closing the pull request, or making the repository private does not change that.

---

## Part 1: Proactive Credential Hygiene (Before You Commit)

The safest secret is one that never enters git. Everything in this part happens on your own machine, before `git commit`.

### 1.1 Environment Variables: Keep Configuration Out of Code

Your code should **read** secrets from its environment, never **contain** them.

```python
# ❌ Don't: the secret is now part of your source code and your git history
db = connect("postgres://admin:SuperSecret123@db.example.org:5432/app")

# ✅ Do: the code only knows the variable's name
import os
db = connect(os.environ["DATABASE_URL"])
```

```javascript
// ❌ Don't
const client = new Postmark("pm_live_abc123...");

// ✅ Do (Node.js)
const client = new Postmark(process.env.POSTMARK_API_KEY);
```

Best practices:

- **One source of truth per environment.** On your laptop, values come from an ignored `.env` file. In CI, they come from GitHub Actions secrets. In the cluster, they come from encrypted Kubernetes secrets. The code is the same everywhere; only the environment changes.
- **Never print secrets.** Don't `console.log(process.env)` or `print(os.environ)`, and don't paste `.env` contents into issues, pull requests, Slack, or chat with an AI assistant.
- **Use separate credentials for development.** Your local `.env` should use a local database and test-mode API keys, never production credentials.
- **Fail loudly when a variable is missing.** `os.environ["DATABASE_URL"]` raises an error if the variable is unset, which is better than silently falling back to a hardcoded default.

### 1.2 `.env.example` Standards

Every project that reads environment variables should commit a **`.env.example`** file. It is the template a new contributor copies to create their own `.env`:

```bash
cp .env.example .env     # then edit .env and fill in real values
```

**How to build a sanitized template:**

1. List **every** variable the project needs, in the same order as your real `.env`.
2. Replace every secret value with an obvious placeholder: something that cannot possibly be mistaken for a real credential.
3. Keep non-secret defaults (ports, local hostnames, feature flags) when they help contributors get started.
4. Add a comment for anything that isn't self-explanatory, including where to get a real value.

```dotenv
# .env.example: copy to .env and fill in real values. Never commit .env.

# Database (local development)
POSTGRES_USER=your_username_here
POSTGRES_PASSWORD=your_password_here
POSTGRES_DB=app_dev
DATABASE_URL=postgres://your_username_here:your_password_here@localhost:5432/app_dev

# Authentication
JWT_SECRET=replace_with_a_long_random_string

# Third-party services (ask your Tech Lead for a test-mode key)
POSTMARK_API_KEY=your_postmark_test_key_here

# Non-secret settings
PORT=3000
```

**Placeholder rules:**

| ✅ Good placeholders | ❌ Bad placeholders |
|---|---|
| `your_password_here` | `password123` (looks like a real, weak password) |
| `replace_with_a_long_random_string` | A real key with a few characters changed |
| `your_postmark_test_key_here` | An expired or "old" real key |
| *(empty)* `API_KEY=` | Your actual development key ("it's only dev") |

> ⚠️ **Never** create `.env.example` by copying your real `.env` and editing it. It is too easy to miss one value. Write the example by hand, or copy only the variable names.

To generate a strong random value for your own `.env` (for example, a `JWT_SECRET`):

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(48))"
```

### 1.3 Bulletproof `.gitignore` Rules

Add these rules to the `.gitignore` at the **root** of every repository. They apply to all subfolders, so `frontend/.env` and `server/.env` are covered too.

```gitignore
# Environment files: ignore every .env variant...
.env
.env.*
# ...but keep the committed templates
!.env.example
!*.example

# Private keys and certificates
*.pem
*.key
id_rsa
id_rsa.*
id_ed25519
id_ed25519.*
!*.pub

# Cloud and service-account credential files
credentials.json
service-account*.json
*.p12
*.pfx
```

How the rules work:

- `.env` and `.env.*` ignore `.env`, `.env.local`, `.env.production`, and every other variant, in any folder.
- Lines starting with `!` are **exceptions**. `!*.example` keeps `.env.example` and `.env.test.example` committable, and `!*.pub` keeps **public** SSH keys (which are safe to share) while ignoring the private ones.
- Order matters: an exception only works if it comes **after** the rule it overrides.

> ⚠️ A rule like `.env.local` (common in templates from Create React App and Next.js) does **not** ignore a plain `.env` file. Check that your `.gitignore` has `.env` itself.

#### How to verify that files are truly untracked

**1. See everything git is ignoring.** `!!` means ignored; `??` means untracked but **not** ignored (it could be committed by `git add .`).

```console
$ git status --ignored --short
?? .env.example
?? app.py
?? id_rsa.pub
!! .env
!! .env.local
!! .env.production
!! credentials.json
!! frontend/.env
!! id_rsa
!! server.pem
!! tls.key
```

**2. Ask git *why* a file is or isn't ignored.** `git check-ignore -v` prints the `.gitignore` file, line number, and rule that matched:

```console
$ git check-ignore -v .env frontend/.env tls.key .env.example
.gitignore:2:.env	.env
.gitignore:2:.env	frontend/.env
.gitignore:10:*.key	tls.key
.gitignore:6:!*.example	.env.example
```

Read the rule carefully: if it starts with `!` (like `!*.example` above), the file is **not** ignored. If `git check-ignore` prints nothing, no rule matches and the file is not ignored.

**3. Watch out for files that are already tracked.** `.gitignore` never applies to a file git is already tracking. In that case `git check-ignore` prints **nothing**, even though a rule exists, and `git status` keeps showing your changes:

```console
$ git status --short
 M .env                          # still tracked, despite .gitignore

$ git check-ignore -v .env       # prints nothing
$ git check-ignore -v --no-index .env
.gitignore:1:.env	.env          # the rule exists, but git ignores it for tracked files

$ git ls-files --error-unmatch .env
.env                             # confirms the file is tracked
```

To stop tracking the file without deleting your local copy:

```bash
git rm --cached .env
git commit -m "Stop tracking .env"
```

> 🚨 `git rm --cached` only stops **future** commits from including the file. If the file was ever pushed with a real secret in it, the secret is still in history. Go to [Part 3](#part-3-emergency-leak-remediation-runbook-if-a-secret-gets-pushed) and revoke it.

### 1.4 Client-Side vs. Server-Side Variables

Some frameworks expose environment variables to the **browser**. Any variable with these prefixes is copied into the JavaScript bundle at build time, and anyone who opens your site can read it with the browser's developer tools:

| Framework | Public prefix | How it's read in code |
|---|---|---|
| Create React App | `REACT_APP_*` | `process.env.REACT_APP_...` |
| Vite (React, Vue, Svelte) | `VITE_*` | `import.meta.env.VITE_...` |
| Next.js | `NEXT_PUBLIC_*` | `process.env.NEXT_PUBLIC_...` |

Each framework's documentation says the same thing: these variables are embedded into the build and must never hold private secrets [4][5][6].

| ✅ Safe in a public variable | ❌ Never in a public variable |
|---|---|
| The URL of your own backend API | Database passwords or connection strings |
| An OAuth **client ID** (public by design) | OAuth **client secrets** |
| A publishable or "public" key a service tells you to use in the browser (for example, Stripe's `pk_...` key) | Secret or server keys (for example, Stripe's `sk_...` key), AWS keys, JWT secrets |
| Feature flags, analytics site IDs | Any token that lets someone write, read private data, or spend money |

If your frontend needs to call a service that requires a secret key, **call your own backend instead**, and have the backend (where the variable has no public prefix) make the request.

> ⚠️ Putting a secret in a `.env` file does **not** make it private if its name starts with `REACT_APP_`, `VITE_`, or `NEXT_PUBLIC_`. The prefix publishes it.

### 1.5 Local Pre-Commit Scanning

A pre-commit hook is a small check that git runs **before** it creates a commit. If the check finds a secret in your staged changes, the commit is refused and nothing is recorded in history.

OSS-SLU maintains a ready-made configuration with a **Gitleaks** secret scanner in [`oss_cicd_automation/Templates/git-hooks`](https://github.com/oss-slu/oss_cicd_automation/tree/main/Templates/git-hooks) [7].

**Set it up once per repository:**

```bash
# 1. Install the pre-commit framework (once per machine)
pip install pre-commit

# 2. From the root of your project, add the config.
#    The file MUST be named .pre-commit-config.yaml (with "yaml", not "yml")
cat > .pre-commit-config.yaml <<'YAML'
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.30.1
    hooks:
      - id: gitleaks
YAML

# 3. Install the hook into this clone (once per clone, on every machine)
pre-commit install

# 4. Optional: scan every file in the repository right now
pre-commit run --all-files
```

> ⚠️ **The file name matters.** `pre-commit` only looks for `.pre-commit-config.yaml`. If you name it `.pre-commit-config.yml`, every commit fails with `No .pre-commit-config.yaml file was found`. If you copy the general template from `oss_cicd_automation`, rename it to `.yaml`.

Commit `.pre-commit-config.yaml` so that your teammates get the same check, and add `pre-commit install` to your project's contributing guide. Each contributor still has to run `pre-commit install` in their own clone. The hook lives in `.git/hooks`, which is never committed.

**What it looks like when a hook blocks a commit.** This output is from a simple test hook (named `block fake secret`) catching a fake key that was staged by mistake:

```console
$ git commit -m "add config"
block fake secret........................................................Failed
- hook id: block-fake
- exit code: 1

.env.sample:1:API_KEY=sk_test_FAKE_1
```

No commit was created. Remove the secret from the file (or unstage the file with `git restore --staged <file>`), then commit again. The Gitleaks hook reports findings the same way, with the file, line, and the rule that matched, and with the secret value redacted.

**Without the pre-commit framework.** If you already have [Gitleaks installed](https://github.com/gitleaks/gitleaks#installing) (for example, `brew install gitleaks`), you can scan your staged changes directly, or the whole history of a repository:

```bash
gitleaks git --pre-commit --staged --redact --verbose   # staged changes only
gitleaks git --redact --verbose .                       # full history of this repository
```

**Handling false positives.** If Gitleaks flags something that is definitely not a secret, such as a documented test fixture, add the finding's fingerprint (printed in the report) to a `.gitleaksignore` file in the repository root, and explain why in the pull request. Never add a real secret to `.gitleaksignore`.

> ⚠️ **Don't use `git commit --no-verify`** to get past the hook. It skips all checks, and the next safety net is GitHub Push Protection ([Part 2](#part-2-working-with-github-push-protection)), which does not recognize every kind of secret.

---

## Part 2: Working with GitHub Push Protection

**Push Protection** is GitHub's server-side safety net. When you run `git push`, GitHub scans the commits you are sending. If they contain a supported secret, GitHub **rejects the push**, and the secret never reaches the repository [8].

Two layers can block you:

- **Repository push protection**, which organization or repository admins turn on, and which the OSS-SLU security team recommends for every project.
- **Push protection for users**, which is on by default for your own GitHub account and blocks supported secrets in pushes to **public** repositories even when the repository has not turned it on [8].

> ✅ **Good news:** if your push was blocked, the secret was **not** published. Your commits never left your machine. Fix them locally (section 2.3) and you're done. You do not need to rotate the secret, unless you also shared it somewhere else, such as Slack or a pull request comment.

### 2.1 What a Blocked Push Looks Like

When Push Protection blocks you, `git push` fails with output in this format (the commit hashes, paths, and URL will be your own):

```console
$ git push origin feature/add-email
remote: error: GH013: Repository rule violations found for refs/heads/feature/add-email.
remote:
remote: - GITHUB PUSH PROTECTION
remote:   —————————————————————————————————————————
remote:     Resolve the following violations before pushing again
remote:
remote:     - Push cannot contain secrets
remote:
remote:       —— Postmark Server API Token ——————————————————————
remote:        locations:
remote:          - commit: 8728dbe67
remote:            path: server/config.js:12
remote:          - commit: 03d69e5d3
remote:            path: server/config.js:12
remote:
remote:        (?) To push, remove secret from commit(s) or follow this URL to allow the secret.
remote:        https://github.com/oss-slu/<repo>/security/secret-scanning/unblock-secret/...
remote:
To github.com:oss-slu/<repo>.git
 ! [remote rejected] feature/add-email -> feature/add-email (push declined due to repository rule violations)
error: failed to push some refs to 'github.com:oss-slu/<repo>.git'
```

How to read it:

- **The secret type** (here, `Postmark Server API Token`) tells you which credential was found.
- **`locations`** lists **every** commit and `file:line` where the secret appears. You must remove it from **all** of them, not just the latest.
- GitHub shows at most five secrets at a time. After you fix them, push again; a second batch may appear [8].
- The **URL** is the bypass link. See the next section before you go near it.

> ℹ️ **Not every `GH0xx` error is a secret.** `remote: error: GH007: Your push would publish a private email address` is a different block: your commits use an email address you have marked private on GitHub. Fix it by setting `git config user.email` to your GitHub `noreply` address and running `git commit --amend --reset-author --no-edit`. It has nothing to do with Push Protection.

### 2.2 The "Do Not Bypass" Rule

Following the URL in the error lets you tell GitHub the secret is **used in tests**, **a false positive**, or something **you'll fix later**, and then click **"Allow me to push this secret."** [8]

> 🚫 **The rule: never click "Allow me to push this secret" to make the warning go away.**

Why:

- **Bypassing publishes the secret.** The moment you push, the secret is public and will be scraped (see [Core Concepts](#the-speed-of-public-compromise)). The block was the last moment it was still private.
- **"I'll fix it later" means "rotate it now."** Once pushed, "fixing" it requires revoking the credential and possibly rewriting history (Part 3). Removing it locally now takes two minutes.
- **It is recorded.** Every bypass, and the reason chosen, is logged by GitHub, and in repositories with secret scanning it is visible to the project's admins and the security team.
- **"Used in tests" is still public.** A real key used in a test is still a real key. Tests should use clearly fake values or a local mock.

**If you genuinely believe it is a false positive** (for example, a published, well-known example token in documentation), **don't bypass it yourself.** Ask your Tech Lead or the security team first. In repositories that use delegated bypass, you will instead see an option to **request** a bypass, which a reviewer must approve [9].

> 🚨 **If you already bypassed** a block for a real secret, treat it as a leak and go to [Part 3](#part-3-emergency-leak-remediation-runbook-if-a-secret-gets-pushed) now.

### 2.3 Safely Removing a Secret from Unpushed Commits

Because the push was rejected, the bad commits exist **only on your machine**, so you are allowed to rewrite them. First, take the secret out of the code: move the value into your ignored `.env` and read it from an environment variable (Part 1.1). Then pick the case that matches the `locations` in the error.

#### Case A: the secret is only in your latest commit

**Option 1: amend the commit.** This replaces the last commit with a corrected one.

```bash
# 1. Edit the file to remove the secret (read it from the environment instead)
# 2. Replace the last commit with the fixed version
git commit --amend --all --no-edit
# 3. Push again
git push
```

**Option 2: undo the commit and redo it.** `git reset HEAD~1` removes the last commit but **keeps all your changes** in your working folder, so you can fix them and commit again.

```bash
git reset HEAD~1          # undo the last commit; your changes stay in your files
git status                # the files from that commit now show as modified or untracked
# fix the secret; if a whole file like .env was committed, add it to .gitignore
git add <the files you want>     # don't use "git add ." until .gitignore is fixed
git commit -m "Add config (reads key from environment)"
git push
```

> ⚠️ Use `git reset HEAD~1`, **not** `git reset --hard HEAD~1`. `--hard` throws away your changes.

#### Case B: the secret is in an earlier commit on your branch

If `locations` lists a commit that is not your latest, amending is not enough: the older commit still contains the secret, and pushing will be blocked again. Rewrite the branch from the **earliest** commit that has the secret, using an interactive rebase.

```bash
# 1. Find the earliest commit that contains the secret.
#    Either use the oldest commit in the error's "locations", or search for the value:
git log --oneline -S "<part of the secret>" --reverse
#    e.g.  ffcf962 add config

# 2. Start an interactive rebase from the commit BEFORE it (note the ~1)
git rebase -i ffcf962~1
```

Your editor opens with a list of commits. On the line for the commit that introduced the secret, change `pick` to `edit`, then save and close:

```text
edit ffcf962 add config
pick ab3a020 add feature
pick 0937a72 more work
```

Git stops at that commit. Fix it, then let git replay the rest:

```bash
# 3. Remove the secret from the file(s), then:
git add <fixed files>
git commit --amend --no-edit
git rebase --continue

# 4. Repeat step 3 if git stops at another commit you marked "edit". Then push:
git push
```

If a later commit also contains the secret (it will appear in `locations`), mark that commit as `edit` too and fix it the same way.

#### Case C: you committed a whole secrets file (such as `.env`)

Remove the file from the commit without deleting your local copy, and ignore it:

```bash
git rm --cached .env
echo ".env" >> .gitignore
git add .gitignore
git commit --amend --no-edit      # if .env was added in your latest commit
# if it was added in an earlier commit, do this inside the interactive rebase from Case B
git push
```

#### Before you push again: double-check

Search everything you are about to push for the secret. No output means it's gone:

```bash
git log -p origin/main..HEAD | grep -n "<part of the secret>"
```

If you use Gitleaks, `gitleaks git --redact --verbose .` scans your whole local history.

> 🔁 **Still blocked?** The secret is in another commit listed in `locations`, or there are more than five secrets and GitHub is showing you the next batch. Read the new error and repeat.

---

## Part 3: Emergency Leak Remediation Runbook (If a Secret Gets Pushed)

Use this runbook when a real secret has reached GitHub: on `main`, on any branch, in a pull request, or after a bypassed Push Protection block. **Work through the steps in order.** Step 1 is the only one that actually stops an attacker; everything after it is cleanup.

| Step | What | Who | When |
|---|---|---|---|
| 1 | Revoke and rotate the secret | You, or whoever controls the account that issued it | **Immediately** |
| 2 | Tell your Tech Lead | You | Right after Step 1, before touching history |
| 3 | Purge the secret from history with `git-filter-repo` | Tech Lead, or you with their go-ahead | Same day |
| 4 | Force-push and coordinate the team | Tech Lead | Immediately after Step 3 |
| 5 | Clear GitHub's cached views and close the alert | Tech Lead or security team | After Step 4 |

### Step 1: Revoke and Rotate Immediately

**Golden Rule #1: assume the secret is already compromised.** It was public from the moment of the push. Deleting the commit, closing the pull request, or making the repository private does not make it safe. Only **revoking** the credential does.

1. **Invalidate the secret at the service that issued it**, so the leaked copy stops working:

   | Leaked secret | How to revoke it |
   |---|---|
   | **GitHub personal access token** | GitHub → **Settings → Developer settings → Personal access tokens** → find the token → **Delete** (or **Regenerate**) |
   | **Harbor robot account** | Harbor → the project → **Robot Accounts** → select the account → **Disable** or **Delete** it, or **refresh its secret**. Ask a Harbor project admin if you can't see this page. |
   | **Database password** | Change the password for that database user, for example in PostgreSQL: `ALTER USER app_user WITH PASSWORD '<new strong password>';`. Then check the database's access logs for logins you don't recognize. |
   | **AWS access key** | AWS console → **IAM → Users → Security credentials → Access keys** → **Deactivate**, then **Delete**. With the CLI: `aws iam update-access-key --user-name <user> --access-key-id <AKIA...> --status Inactive`, then `aws iam delete-access-key --user-name <user> --access-key-id <AKIA...>` |
   | **Stripe secret key** | Stripe dashboard → **Developers → API keys** → **Roll key** on the secret key |
   | **Anything else** (Postmark, Cloudflare, Google, JWT signing secret, SSH key) | Use the provider's dashboard to delete or roll the key. For a JWT secret, generate a new one (Part 1.2); all existing sessions will be logged out. For an SSH key, remove the public key from every server's `authorized_keys` and from GitHub. |

2. **Issue and configure a new secret.** Create the replacement, then put it where the application reads it: your local `.env`, the repository's **GitHub Actions secrets** (repository **Settings → Secrets and variables → Actions**), and the deployment's encrypted secret. Never put the new value in a commit.
3. **Check for misuse.** Look at the provider's usage or audit logs for activity you don't recognize, such as unexpected logins, API calls, cloud instances, or charges, from the time of the push onward.
4. **Write down** what leaked, when it was pushed, when it was revoked, and where the new value lives. Your Tech Lead will need this.

> ⚠️ If you **cannot** revoke the secret yourself (for example, it belongs to a shared organization account), **don't wait**: contact your Tech Lead and the security team immediately, and tell them it is a live leak. The Incident Response Plan requires same-day rotation, and immediate escalation for tokens with organization-wide access.

### Step 2: Coordinate with Your Tech Lead

Tell your **Tech Lead** (or the security / DevSecOps lead) **before** anyone rewrites history. Send them what you wrote down in Step 1.4: what leaked, which repository and branch, the commit hash, and whether the secret has been revoked.

Why history rewriting needs a lead:

- **It affects everyone.** Rewriting history changes the hash of every commit after the leak. Every teammate's clone and every open pull request will be out of date.
- **`main` is protected.** OSS-SLU's [branch protection baseline](../standards/branch-protection-guide.md) blocks force pushes to `main`. Only a repository admin can lift that rule temporarily, and must turn it back on afterward.
- **It may not be needed.** If the secret has been revoked and the repository's history is shared widely, the lead may decide that rotation is enough and skip Steps 3–5. GitHub itself only helps remove data when rotating the credential can't mitigate the risk [1].

Agree on a time when nobody is pushing, and ask teammates to **merge or close open pull requests** first if possible [1].

### Step 3: Purge History with `git-filter-repo`

`git-filter-repo` is the history-rewriting tool recommended by the Git project and by GitHub [1][10].

> **Why not `git filter-branch`?** The Git documentation itself warns that `git filter-branch` has many pitfalls that can silently corrupt a rewrite, is extremely slow, and recommends using `git filter-repo` instead [10]. The **BFG Repo-Cleaner** is a faster community alternative for simple cases, but `git-filter-repo` handles both "remove this file" and "replace this text", and supports GitHub's sensitive-data workflow directly [1].

#### 3.1 Install `git-filter-repo`

```bash
pip install git-filter-repo        # or: brew install git-filter-repo
git filter-repo --version          # confirm it's installed
```

#### 3.2 Start from a fresh mirror clone

Work in a **brand-new** clone, not the folder you've been developing in. `git-filter-repo` refuses to run in a clone with local history, as a safety check:

```console
$ git filter-repo --invert-paths --path .env
Aborting: Refusing to destructively overwrite repo history since
this does not look like a fresh clone.
```

A **mirror** clone copies every branch and tag, so the whole repository is cleaned at once:

```bash
git clone --mirror https://github.com/oss-slu/<repo>.git
cd <repo>.git
```

#### 3.3 Option A: replace the secret text everywhere

Use this when the secret is inside a file that should stay, such as a hardcoded key in `config.js`.

Create a file **outside** the repository, for example `../expressions.txt`, with one secret per line. Each line is `the secret==>what to replace it with`:

```text
<the-leaked-key-value>==>***REMOVED***
postgres://admin:SuperSecret123@==>postgres://***REMOVED***@
```

Then run:

```bash
git filter-repo --sensitive-data-removal --replace-text ../expressions.txt
```

Every occurrence, in every file, commit, branch, and tag, is replaced. In a test repository, a hardcoded key in the commit that introduced it became:

```console
$ git show <old-commit>:config.py
API_KEY = "***REMOVED***"
```

> ⚠️ Delete `expressions.txt` when you're done. It contains the secret.

#### 3.4 Option B: purge an entire file

Use this when a file should never have been committed, such as `.env`, `credentials.json`, or a private key:

```bash
git filter-repo --sensitive-data-removal --invert-paths --path .env
```

`--path .env` selects the file and `--invert-paths` means "keep everything **except** it". Use the file's full path from the repository root (for example, `--path server/.env`), and add one `--path` per file. You can run Option A and Option B one after the other in the same clone.

> ℹ️ **About `--sensitive-data-removal`.** This flag (in recent versions of `git-filter-repo`) makes the tool fetch every ref GitHub has, keep your `origin` remote, and print the information GitHub Support needs in Step 5, including the **"First Changed Commit(s)"**. Copy that output somewhere safe. If your version doesn't support the flag, run the same commands without it. In that case `git-filter-repo` **removes** the `origin` remote, so add it back before pushing: `git remote add origin https://github.com/oss-slu/<repo>.git`.

#### 3.5 Verify before you push

Search all of the rewritten history for the secret. No output means it's gone:

```bash
git grep -n "<part of the secret>" $(git rev-list --all)
git log --all --oneline -- .env       # should print nothing for a purged file
```

### Step 4: Force-Push and Coordinate the Team

If `main` is protected, a repository admin must **temporarily allow force pushes** first (repository **Settings → Rules** or **Branches**), and turn the protection back on immediately after this step.

From the mirror clone, overwrite every branch and tag on GitHub with the cleaned history:

```bash
git push --force --mirror origin
```

From a regular (non-mirror) fresh clone, push branches and tags separately instead:

```bash
git push origin --force --all
git push origin --force --tags
```

> ℹ️ On GitHub, a mirror push will report errors for `refs/pull/...`. That is expected: GitHub keeps pull request references read-only. Removing those is part of Step 5.

**Then coordinate the team.** Old clones still contain the secret. If anyone runs `git pull` and then `git push` from an old clone, **the secret comes back** [1]. Send everyone this message:

> History on `<repo>` was rewritten to remove a leaked secret (it has already been revoked). Please **don't push** from your current clone. Save any unpushed work as a patch (`git format-patch origin/<branch>`) or copy the files elsewhere, **delete your local clone, and clone again**. For open pull request branches: re-clone, recreate your branch from the new `main`, re-apply your changes, and force-push your branch.

Also:

- Ask the owners of any **forks** to delete and re-create them. GitHub cannot clean other people's forks [1].
- Turn the **branch protection rule back on** for `main`.

### Step 5: GitHub Cache Invalidation and Secret Alert Closure

Even after the force push, GitHub can still show the old commits in **cached views**, for example if someone has a link to the old commit hash, and through references from **pull requests** [1].

**Contact GitHub Support to clear cached commit views.** A repository admin (or the security team) opens a request at [support.github.com](https://support.github.com/request) and asks for removal of sensitive data, including:

- the repository owner and name;
- the **First Changed Commit(s)** printed by `git-filter-repo` in Step 3;
- confirmation that the secret has been **revoked or rotated**.

GitHub Support only removes cached data when rotating the credential can't fully mitigate the risk [1], which is one more reason Step 1 always comes first.

**Close the Secret Scanning alert as "Revoked".** If GitHub raised a secret scanning alert for the leak:

1. Go to the repository's **Security** tab → **Secret scanning**.
2. Open the alert for the leaked secret.
3. Click **Close as** → **Revoked**, and add a short comment (for example, *"Rotated on 2026-11-24; history purged; see incident note."*).

Choose **Revoked** only after Step 1 is actually done. Don't close a real leak as "False positive" or "Used in tests".

**Finally, prevent a repeat.** Add the file pattern to `.gitignore` (Part 1.3), add a `.env.example` (Part 1.2), install the pre-commit hook (Part 1.5), and ask your Tech Lead to confirm Push Protection is on for the repository.

---

## Part 4: Quick Reference / Developer Cheat Sheet

Bookmark this section. Use it during onboarding and when reviewing pull requests.

### The Five Rules

1. **Secrets live in environment variables, never in code.** Real values go in an ignored `.env`; only `.env.example` with placeholders is committed.
2. **`REACT_APP_*`, `VITE_*`, and `NEXT_PUBLIC_*` are public.** Never put a secret in them.
3. **Never bypass Push Protection** to silence a warning. Fix your local commits instead.
4. **If a secret is pushed, revoke it first.** Deleting it does not make it safe.
5. **Never rewrite shared history alone.** Tell your Tech Lead before using `git-filter-repo` or force-pushing.

### Before You Commit

| ✅ Check | Command or action |
|---|---|
| `.env` and key files are ignored | `git check-ignore -v .env` → should print a rule **without** a leading `!` |
| Nothing secret is about to be committed | `git status --ignored --short` → `.env` should show as `!!`, never as `??` or `A` |
| The file isn't already tracked | `git ls-files --error-unmatch .env` → should say it's **not** known to git |
| Your diff contains no secrets | `git diff --staged` → read it before committing |
| The pre-commit hook is installed | `pre-commit install` (once per clone); config named `.pre-commit-config.yaml` |
| New variables are documented | Added to `.env.example` with a placeholder value |

### Command Reference

| I want to… | Command |
|---|---|
| See which files git ignores | `git status --ignored --short` |
| See which rule ignores a file | `git check-ignore -v <file>` |
| Check the rule for a file that's already tracked | `git check-ignore -v --no-index <file>` |
| Stop tracking a file but keep it locally | `git rm --cached <file>` then commit |
| Generate a random secret for `.env` | `python3 -c "import secrets; print(secrets.token_urlsafe(48))"` |
| Scan staged changes with Gitleaks | `gitleaks git --pre-commit --staged --redact --verbose` |
| Fix a secret in my **last** unpushed commit | Edit the file, then `git commit --amend --all --no-edit` |
| Undo my last unpushed commit but keep the changes | `git reset HEAD~1` |
| Fix a secret in an **earlier** unpushed commit | `git rebase -i <commit>~1`, mark it `edit`, fix, `git commit --amend`, `git rebase --continue` |
| Find which commits contain a value | `git log --oneline -S "<part of secret>" --reverse` |
| Replace a secret in all history *(Tech Lead)* | `git filter-repo --sensitive-data-removal --replace-text ../expressions.txt` |
| Remove a file from all history *(Tech Lead)* | `git filter-repo --sensitive-data-removal --invert-paths --path <file>` |
| Push rewritten history *(Tech Lead)* | `git push --force --mirror origin` |

### What to Do When…

| Situation | Is the secret public? | Do this |
|---|---|---|
| The pre-commit hook blocked my commit | No | Remove the secret or unstage the file, then commit again (Part 1.5) |
| `git push` failed with **GH013 … Push cannot contain secrets** | No | Fix your local commits (Part 2.3), then push. **Don't bypass.** |
| `git push` failed with **GH007 … private email address** | Not a secret issue | Use your GitHub `noreply` email and `git commit --amend --reset-author --no-edit` |
| I clicked "Allow me to push this secret" | **Yes** | Go to Part 3, Step 1 |
| I pushed a secret (any branch, any fork, any PR) | **Yes** | **Part 3, Step 1: revoke now.** Then tell your Tech Lead. |
| I found a secret someone else pushed | **Yes** | Tell the Tech Lead and security team privately. Don't post it in an issue or channel. |
| I pasted a secret in Slack, an issue, or a PR comment | **Yes** | Revoke it (Part 3, Step 1) and delete the message |

### Pull Request Review Checklist

Reviewers, check every pull request for:

- [ ] No hardcoded keys, tokens, passwords, or connection strings in the diff
- [ ] No new `.env`, `*.pem`, `*.key`, `id_rsa`, or `credentials.json` files
- [ ] New environment variables are added to `.env.example` with placeholders
- [ ] No secrets in `REACT_APP_*`, `VITE_*`, or `NEXT_PUBLIC_*` variables
- [ ] Workflows use `${{ secrets.NAME }}`, never a literal value
- [ ] No secrets printed in logs, test output, or error messages
- [ ] The secret scanning check (if the repository has one) passed

If you find a real secret in a pull request, **don't** just leave a review comment asking for it to be removed: it is already public. Tell the author to follow Part 3, Step 1, and tell the Tech Lead.

---

## References

[1] GitHub Docs, "Removing sensitive data from a repository." https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository

[2] Palo Alto Networks Unit 42, "EleKtra-Leak Cryptojacking Campaign Targets AWS IAM Credentials Exposed on GitHub," October 2023. https://unit42.paloaltonetworks.com/malicious-operations-of-exposed-iam-keys-cryptojacking/

[3] M. Meli, M. R. McNiece, and B. Reaves, "How Bad Can It Git? Characterizing Secret Leakage in Public GitHub Repositories," *NDSS*, 2019. https://www.ndss-symposium.org/ndss-paper/how-bad-can-it-git-characterizing-secret-leakage-in-public-github-repositories/

[4] Create React App, "Adding Custom Environment Variables." https://create-react-app.dev/docs/adding-custom-environment-variables/

[5] Vite, "Env Variables and Modes." https://vite.dev/guide/env-and-mode

[6] Next.js, "Environment Variables: Bundling Environment Variables for the Browser." https://nextjs.org/docs/app/guides/environment-variables

[7] OSS-SLU, `oss_cicd_automation`: pre-commit templates and secret scanning guide. https://github.com/oss-slu/oss_cicd_automation

[8] GitHub Docs, "Working with push protection from the command line." https://docs.github.com/en/code-security/how-tos/secure-your-secrets/work-with-leak-prevention/working-with-push-protection-from-the-command-line

[9] GitHub Docs, "About bypass requests for push protection." https://docs.github.com/en/code-security/concepts/secret-security/about-bypass-requests-for-push-protection

[10] Git documentation, "git-filter-branch" (warning and recommendation to use `git filter-repo`). https://git-scm.com/docs/git-filter-branch

**Related OSS-SLU documents:** [Security Risk Register](../risk_assessment.md) (R-01), [Branch Protection Guide](../standards/branch-protection-guide.md), [Case Study: Secret Scanning and Push Protection](../case_studies/secret_scanning_push_protection_case_study_fall2026.md), [White Paper: Zero-Trust Secret Governance](../white_papers/zero_trust_secret_governance_white_paper.md), and the [Incident Response Plan](../incident_response_plan.pdf).
