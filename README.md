# 🍴 gr8food portal

Open the page using link : https://gr8food-portal.onrender.com/

## 🌟 Overview

gr8food portal is designed to provide a seamless dining experience for customers and a smooth management interface for kitchen staff and administrators.

* **Customer Portal**: Browse delicious artisan dishes, customize orders, and place delivery requests.
* **Admin Dashboard**: Manage menu items, track real-time orders, monitor kitchen operations, and adjust restaurant settings.
* **Security & Auth Guard**: Role-based access control ensuring customers and staff only access their designated views.

---

## 💡 The Challenge & How It Was Solved

### 🧩 The Problem
When testing the live portal (`gr8food-portal.onrender.com`), visiting the login page would sometimes open with the administrator's credentials (`username` and `password`) already filled in and "stitched" into the input boxes.

At first glance, it looked as if the admin credentials might be hardcoded into the site and visible to anyone receiving the link. 

In reality:
* Modern browsers (like Google Chrome and Microsoft Edge) aggressively search for login inputs (`autocomplete="username"`, `type="password"`) and automatically inject whatever credentials the site owner previously saved on their computer.
* However, having saved credentials automatically appear on page load poses a visual and privacy risk, creating confusion when sharing links or testing on shared devices.

### 🛠️ The Solution (Simple & Humanized)
We updated the login system to enforce a **clean-slate policy** so the form opens completely blank for everyone, without deleting or breaking any existing login logic:

1. **Autofill Deflection**: Added `autocomplete="off"` and decoy helper inputs that deflect aggressive browser password managers from latching onto the main fields.
2. **Read-Only Gatekeeper**: The input fields load with an initial `readonly` state. Browsers refuse to auto-inject saved passwords into read-only fields on page load. The very moment a real person clicks, taps, or focuses on the box, the attribute is removed seamlessly so they can type normally.
3. **Clean-Slate Reset Routine**: Added a lightweight startup script that automatically clears input values on page load, browser back/forward navigation (`pageshow`), and DOM initialization.
4. **Clean Visuals**: Normalized browser autofill styles to prevent unwanted blue background flashes.

**Result**: Every person opening the link receives a pristine, 100% blank, and secure sign-in page.

---

## 🚀 Tech Stack

* **Frontend**: Vanilla HTML5, CSS3 (Modern Earthy Cream & Muted Khaki Palette), JavaScript (ES6+)
* **Backend**: Node.js, Express.js
* **Storage**: Local JSON database store (`gr8food_db.json`) with optional PostgreSQL database integration
* **Deployment**: Hosted on Render

---


## 📄 License
This project is for gr8food portal operations and dining management.
