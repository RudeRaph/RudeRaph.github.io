---
layout: default
title: Home
---

<section class="hero">
  <h1>RudeRaph</h1>
  <p class="tagline">Penetration Testing</p>
  <p>Keep learning and keep owning.</p>
  <p>
    <a href="/resume.pdf">Download Resume</a> ·
    <a href="https://github.com/RudeRaph">GitHub</a>
  </p>
</section>

<section class="certifications">
  <h2>Certifications & Pro Labs</h2>
  <ul>
    <li><strong>CPTS</strong> — Certified Penetration Testing Specialist, HTB Academy — Completed</li>
    <li><strong>CDSA</strong> — Certified Defensive Security Analyst, HTB Academy — Completed</li>
    <li><strong>CWPE</strong> — HTB Academy — In Progress</li>
    <li><strong>CWES</strong> — HTB Academy — In Progress</li>
    <li><strong>CJCA</strong> — HTB Academy — In Progress</li>
    <li><strong>HTB Pro Lab: Dante</strong> — Completed</li>
    <li><strong>HTB Pro Lab: P.O.O</strong> — Completed</li>
    <li><strong>HTB Pro Lab: Offshore</strong> — In Progress</li>
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
