---
layout: default
title: Home
---

<section class="hero">
  <h1>Your Name</h1>
  <p class="tagline">Cybersecurity | Penetration Testing | HTB Enthusiast</p>
  <p>Short intro paragraph. Who you are, what you focus on (e.g. Active Directory attacks, web app security, binary exploitation), and what you're looking for (e.g. "seeking a pentesting/red team role").</p>
  <p>
    <a href="/resume.pdf">Download Resume</a> ·
    <a href="https://linkedin.com/in/yourusername">LinkedIn</a> ·
    <a href="https://github.com/yourusername">GitHub</a>
  </p>
</section>

<section class="certifications">
  <h2>Certifications & Pro Labs</h2>
  <ul>
    <li><strong>Certification Name</strong> — Issuing Org, Year</li>
    <li><strong>HTB Pro Lab: Dante</strong> — Completed, Year</li>
    <li><strong>Certification Name</strong> — Issuing Org, Year</li>
  </ul>
</section>

<section class="tools">
  <h2>Featured Tools</h2>
  <div class="card-grid">
    <div class="card">
      <h3><a href="https://github.com/yourusername/tool-repo">Tool Name</a></h3>
      <p>One or two sentences on what it does and why you built it.</p>
      <p class="tech">Python · Requests · argparse</p>
    </div>
  </div>
</section>

<section class="writeups-preview">
  <h2>Recent Writeups</h2>
  <ul>
    {% for writeup in site.writeups limit:5 %}
      <li>
        <a href="{{ writeup.url }}">{{ writeup.title }}</a>
        <span class="meta">{{ writeup.difficulty }} · {{ writeup.os }}</span>
      </li>
    {% endfor %}
  </ul>
  <p><a href="/writeups.html">View all writeups →</a></p>
</section>
