#!/bin/bash
# OptimEngine WP-CLI
read -p 'Site URL (example.com): ' url
read -p 'Site Title: ' title
read -p 'WP Admin Username: ' admin_user
read -p 'WP Admin Password: ' admin_password
read -p 'WP Admin Email: ' admin_email
read -p 'Database Host: ' dbhost
read -p 'Database Name: ' dbname
read -p 'Database User: ' dbuser
read -p 'Database Password: ' dbpass
read -p 'Database Prefix (wp_) :' dbprefix

echo Ok. Starting installation of $title on $url.

# download, configure and install
echo Downloading WordPress...
sleep 2
wp core download
sleep 3
echo Configuring WordPress
sleep 2
wp core config --dbhost=$dbhost --dbname=$dbname --dbuser=$dbuser --dbpass=$dbpass --dbprefix=$dbprefix
sleep 3
echo Installing WordPress
sleep 2
wp core install --url=$url --title="$title" --admin_user=$admin_user --admin_password=$admin_password --admin_email=$admin_email
sleep 3
# delete default installed plugins and themes we don't need
echo Removing Default WordPress Plugins and Themes
sleep 2
wp plugin delete hello-dolly akismet
wp theme delete twentyfourteen twentyfifteen
sleep 3

# installing recommended plugins
echo Installing Required and Recommended Plugins
sleep 2
wp plugin install seo-by-rank-math nginx-helper
wp plugin activate nginx-helper
sleep 3
# delete all the default sidebar widgets
echo Deleting Default Sidebar Widgets, Post and Pages
sleep 2
wp widget delete search-2 recent-posts-2 archives-2 categories-2 meta-2

# delete the example post and example page
wp post delete 1 2 --force
# make a new page for the homepage and blog page
sleep 3
echo Working on final configurations 
sleep 2
wp post create --post_type=page --post_title='Welcome To OptimEngine' --post_status='publish'
# make those two pages the default for Home and Blog
wp option update show_on_front "page"
wp option update page_on_front "4"
# clear out "Just Another WordPress Blog" BS
wp option delete blogdescription
# set the timezone
wp option update timezone_string "America/New_York"
# we're usually starting with a development site - hide it from search engines
wp option update blog_public "on"
# update the permalink structure
wp rewrite structure '/%postname%/'

echo WordPress Installed and Configured Successfuly
