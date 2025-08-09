# AppSec Engineer Blog

A professional Jekyll blog focused on application security, secure coding practices, and cybersecurity insights. Built with GitHub Pages compatibility and markdown support for easy content management.

## 🚀 Quick Start

### Option 1: Deploy to GitHub Pages (Recommended)

1. **Create a new repository** on GitHub named `username.github.io` (replace `username` with your GitHub username)

2. **Clone the repository** locally:
   ```bash
   git clone https://github.com/username/username.github.io.git
   cd username.github.io
   ```

3. **Add all the blog files** to your repository (copy all files from this blog structure)

4. **Configure the site** by editing `_config.yml`:
   ```yaml
   title: Your Blog Title
   email: your-email@example.com
   description: Your blog description
   url: "https://username.github.io"
   github_username: your_github
   linkedin_username: your_linkedin
   twitter_username: your_twitter
   ```

5. **Customize the About page** by editing `about.md` with your information

6. **Push to GitHub**:
   ```bash
   git add .
   git commit -m "Initial blog setup"
   git push origin main
   ```

7. **Enable GitHub Pages**:
   - Go to repository Settings > Pages
   - Select "Deploy from a branch"
   - Choose "main" branch and "/ (root)" folder
   - Click Save

Your blog will be live at `https://username.github.io` in a few minutes!

### Option 2: Local Development

1. **Install Ruby and Bundler** (if not already installed):
   ```bash
   # On macOS with Homebrew
   brew install ruby
   gem install bundler

   # On Ubuntu/Debian
   sudo apt-get install ruby-full build-essential zlib1g-dev
   gem install bundler
   ```

2. **Install dependencies**:
   ```bash
   bundle install
   ```

3. **Run locally**:
   ```bash
   bundle exec jekyll serve
   ```

4. **Open your browser** to `http://localhost:4000`

## 📝 Creating Blog Posts

### Writing Your First Post

1. **Create a new file** in the `_posts` directory with the format: `YYYY-MM-DD-title.md`
   
   Example: `_posts/2025-08-09-my-first-security-post.md`

2. **Add front matter** at the top:
   ```markdown
   ---
   layout: post
   title: "Your Post Title"
   date: 2025-08-09 10:00:00 +0000
   categories: [security, web-security]
   tags: [owasp, secure-coding, vulnerabilities]
   author: Your Name
   excerpt: "A brief description of your post that appears in previews."
   ---
   ```

3. **Write your content** in Markdown below the front matter

4. **Commit and push** to publish:
   ```bash
   git add _posts/2025-08-09-my-first-security-post.md
   git commit -m "Add new blog post"
   git push origin main
   ```

### Markdown Features Supported

- **Headers**: `# ## ### ####`
- **Code blocks**: Triple backticks with language specification
- **Tables**: Standard markdown tables
- **Links**: `[text](url)`
- **Images**: `![alt](image-url)`
- **Lists**: Numbered and bullet points
- **Blockquotes**: `>`
- **Bold/Italic**: `**bold**` and `*italic*`

### Code Syntax Highlighting

The blog supports syntax highlighting for many languages:

```python
def secure_function(user_input):
    # Input validation
    if not validate_input(user_input):
        raise ValueError("Invalid input")
    return process_input(user_input)
```

```javascript
// Secure cookie configuration
app.use(session({
  secret: process.env.SESSION_SECRET,
  secure: true,
  httpOnly: true,
  maxAge: 1800000 // 30 minutes
}));
```

## 🎨 Customization

### Changing the Theme Colors

Edit `assets/css/style.scss` and modify the CSS variables:

```scss
:root {
  --bg-color: #0d1117;          // Background color
  --surface-color: #161b22;     // Card/surface color
  --text-color: #c9d1d9;        // Main text color
  --accent-color: #58a6ff;      // Link/accent color
  // ... other colors
}
```

### Adding Custom Pages

1. **Create a new markdown file** in the root directory (e.g., `speaking.md`)
2. **Add front matter**:
   ```markdown
   ---
   layout: page
   title: Speaking
   permalink: /speaking/
   ---
   ```
3. **Add the page to navigation** by editing `_includes/header.html`

### Modifying the Navigation Menu

Edit `_includes/header.html` and update the navigation links:

```html
<div class="trigger">
  <a class="page-link" href="{{ "/" | relative_url }}">Home</a>
  <a class="page-link" href="{{ "/about/" | relative_url }}">About</a>
  <a class="page-link" href="{{ "/blog/" | relative_url }}">Blog</a>
  <a class="page-link" href="{{ "/contact/" | relative_url }}">Contact</a>
  <!-- Add more links as needed -->
</div>
```

## 📊 SEO and Analytics

### SEO Optimization

The blog includes built-in SEO optimization:
- Meta tags for social sharing
- Structured data markup
- XML sitemap generation
- RSS feed

### Adding Google Analytics

1. **Get your Google Analytics tracking ID**
2. **Add it to `_config.yml`**:
   ```yaml
   google_analytics: GA_MEASUREMENT_ID
   ```

### Social Media Integration

Update your social media links in `_config.yml`:
```yaml
github_username: your_github
linkedin_username: your_linkedin  
twitter_username: your_twitter
```

## 🔒 Security Features

This blog template includes several security best practices:

- **Secure Headers**: Implemented via the theme
- **Content Security Policy**: Ready for implementation
- **No External Dependencies**: Minimal external resources
- **Static Site**: No server-side vulnerabilities
- **HTTPS**: Enforced by GitHub Pages

## 📁 File Structure

```
├── _config.yml              # Jekyll configuration
├── _includes/               # Reusable components
│   ├── head.html
│   ├── header.html
│   ├── footer.html
│   └── social.html
├── _layouts/                # Page layouts
│   ├── default.html
│   ├── page.html
│   └── post.html
├── _posts/                  # Blog posts (markdown)
│   ├── 2025-08-01-owasp-top10-guide.md
│   └── 2025-07-15-secure-code-review.md
├── _sass/                   # Sass partials (auto-generated)
├── assets/
│   └── css/
│       └── style.scss       # Custom styles
├── index.html               # Homepage
├── about.md                 # About page
├── blog.html                # Blog listing page  
├── contact.md               # Contact page
├── Gemfile                  # Ruby dependencies
└── README.md               # This file
```

## 🎯 Content Ideas for Application Security Blog

### Beginner Topics
- "Introduction to Application Security"
- "Common Web Vulnerabilities Explained"
- "Secure Coding Basics for Developers"
- "Understanding HTTPS and TLS"

### Intermediate Topics  
- "Implementing OAuth 2.0 Securely"
- "Container Security Best Practices"
- "API Security Testing Guide"
- "Database Security Fundamentals"

### Advanced Topics
- "Advanced Threat Modeling Techniques"
- "Zero Trust Architecture Implementation"  
- "Cloud Security Automation"
- "AI/ML Security Considerations"

### Practical Guides
- "Setting Up SAST Tools in CI/CD"
- "Incident Response for Security Teams"
- "Compliance Frameworks Comparison"
- "Security Metrics That Matter"

## 🤝 Contributing

If you find issues or have suggestions:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/improvement`
3. **Make changes and commit**: `git commit -m "Add improvement"`
4. **Push to branch**: `git push origin feature/improvement`
5. **Create a Pull Request**

## 📄 License

This blog template is open source and available under the [MIT License](https://opensource.org/licenses/MIT).

## 📞 Support

If you need help setting up your blog:

- **Create an issue** in the repository
- **Check the Jekyll documentation**: [https://jekyllrb.com/docs/](https://jekyllrb.com/docs/)
- **GitHub Pages documentation**: [https://docs.github.com/en/pages](https://docs.github.com/en/pages)

---

**Happy blogging and stay secure! 🔐**