🚑 QuickResponse: Emergency Dispatch System
This project is a multi-page, role-based front-end application for a modern emergency medical dispatch platform. It utilizes a cohesive dark navy theme and responsive design principles, implemented entirely with HTML, CSS (Tailwind CDN), and vanilla JavaScript.

The application provides distinct interfaces for Public Users, Ambulance Drivers, and Dispatchers, tied together by a central login system.

🛠️ Technology Stack
HTML5: Structural Markup

CSS3: Custom styling for visual consistency

Tailwind CSS (CDN): Used for rapid, modern, utility-first styling across all pages.

Vanilla JavaScript: Used for dynamic functionality, form validation, and complex dashboard state management (e.g., active trips, availability toggles, form switching).

Font Awesome: Used for all icons across the project.

📂 Project Structure Overview
The project consists of 6 self-contained HTML files, each representing a primary view.

File

Description

Roles

Key Features

index.html

Homepage / Marketing Landing. Primary entry point for public users.

Public

Sticky Navbar, Hero Section, "How It Works" Timeline, Footer.

about.html

About Us Page. Details the company's mission and key metrics.

Public

Dark-themed Mission/Vision Cards, Trusted By Thousands stats grid.

services.html

Services Page. Outlines core service features and benefits.

Public

Responsive grid layout for feature cards, consistent dark theme.

contact.html

Contact Us Page. Provides contact information and a detailed message form.

Public

Dual-column layout with contrasting white form card on a dark background.

faqs.html

FAQs Page. Collapsible accordion for common questions.

Public

Pure CSS/JS implementation of the collapsible FAQ component.

login.html

Authentication Portal. Handles both Login and complex Multi-Role Signup.

All Roles

Form switching (Login/Register), Conditional fields based on selected role (Patient, Driver, Dispatcher), Redirection logic.

user.html

Patient/User Dashboard.

Patient/User

Quick Ambulance Request form, Active Trip monitoring (progress bar, driver info), Health Profile, Trip History.

driver.html

Driver Dashboard.

Driver

Availability Toggle, Real-time Trip Request Modal (with countdown), Active Trip progression management, Earnings & Vehicle Stats.

dispatcher.html

Dispatcher Dashboard.

Dispatcher

Fleet Overview (Ambulance status/location), Incoming Request Queue (prioritization/assignment), Active Trip Monitoring, System Alerts, Broadcast messaging.

✨ Key Design Principles & Features
1. Consistent Styling
All pages adhere to a single, professional dark navy (#1f253e) theme with primary red (#f44336) accents. The navigation bar is sticky across all marketing pages for easy access to the "Request Ambulance" button.

2. Multi-Role Authentication
The login.html file implements dynamic logic to handle the three primary user types:

Login: Simulates authentication and redirects the user to their respective dashboard based on a determined role.

Sign Up: Displays conditional form fields (e.g., medical info for Patients, license details for Drivers, and employee IDs for Dispatchers) based on the role selection.

3. Dynamic Dashboards (JavaScript-Powered)
Dashboard

Core Functionality Replicated

User (user.html)

Quick booking form, Active Trip Card with status simulation (pending, accepted, enroute), Driver details, and Trip History rendering.

Driver (driver.html)

Availability Switch (Online/Offline), Simulated Trip Request Modal with a live countdown timer, and sequential Active Trip Stage Progression (e.g., 'Arrived at Pickup' button).

Dispatcher (dispatcher.html)

Fleet Overview (status colors), Incoming Request Queue (prioritized list with assignment forms), and Active Trips monitor for resource allocation.

FAQs (faqs.html)

Fully functional Collapsible Accordion built entirely with CSS and JavaScript for a smooth, native feel.

🚀 How to Run the Project
Since this project consists of self-contained HTML files with embedded CSS and JavaScript, no complex build process is required.

Clone the repository (if applicable) or save the files locally.

Open any of the following files directly in your web browser:

index.html (Homepage)

about.html

contact.html

login.html (Authentication Gateway)

From the login.html page,
