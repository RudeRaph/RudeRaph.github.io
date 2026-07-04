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
      <h3><a href="https://github.com/RudeRaph/dmslider">dmslider.sh</a></h3>
      <p>Modular recon pipeline — nmap, web enum, vhost fuzzing, and CVE lookups in one report.</p>
      <p class="tech">Bash · nmap · gobuster · ffuf</p>
    </div>
    <div class="card">
      <h3><a href="https://github.com/RudeRaph/auto-ligolo">auto-ligolo.sh</a></h3>
      <p>Interactive Ligolo-ng pivot setup — from binary download to live tunnel.</p>
      <p class="tech">Bash · Ligolo-ng</p>
    </div>
    <div class="card">
      <h3><a href="https://github.com/RudeRaph/thinpeas">thinpeas.sh</a></h3>
      <p>Focused Linux privesc enumeration — only actionable findings, no noise.</p>
      <p class="tech">Bash · Linux privesc</p>
    </div>
  </div>
  <p><a href="/tools.html">View all tools →</a></p>
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
