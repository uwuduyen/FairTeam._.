# FairTeam — Full Functional v2

FairTeam is an evidence-based student team contribution platform.

## Core flow
Plan → Work → Record Evidence → Leader Review → Fair Score → Contribution Report

## Included
- Real signup/login/logout with hashed passwords and sessions
- Role-based Leader / Member team membership
- Team creation: creator becomes Leader automatically
- Invite links tied to invited email
- Team tasks with deadline, priority, progress and Effort 1–5
- Evidence submission and actual effort
- Mandatory Leader verification for submitted tasks
- Request Changes + resubmission
- Review history / evidence trail
- Member Dashboard with Leader Reviews
- Leader Dashboard with Needs Your Review
- Calendar with Month / Week / Day views
- Team tasks, meetings/events and personal notes
- Calendar detail modal, meeting link and delete/remove
- Peer Review with 1–5 criteria
- Contribution calculation and factor breakdown
- Contribution Report / print-to-PDF
- Light / Night theme
- Responsive left sidebar navigation

## Run locally
Requires Node.js 24 LTS or newer supported Node.js.

```bash
npm install
npm start
```

Open `http://localhost:3000`.

## GitHub / deployment
Commit the source files to GitHub. Do not commit `node_modules/`, `.env`, or the generated SQLite database file.

For an internet-accessible multi-user deployment, use a Node-compatible host and a persistent production database. The local SQLite file is intended for local development/testing.
