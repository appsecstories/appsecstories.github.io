source "https://rubygems.org"

# GitHub Pages compatible version
gem "github-pages", "~> 228", group: :jekyll_plugins

# Ruby 3.4 compatibility - add missing default gems
gem "csv"
gem "base64" 
gem "bigdecimal"

# Windows compatibility
platforms :windows do
  gem "tzinfo", ">= 1", "< 3"
  gem "tzinfo-data"
end

# Plugins supported by GitHub Pages
group :jekyll_plugins do
  gem "jekyll-feed", "~> 0.12"
  gem "jekyll-sitemap"
  gem "jekyll-seo-tag"
  gem "jekyll-paginate"
  gem "jekyll-include-cache"
end

# Development gems
group :development do
  gem "webrick", "~> 1.7"
end