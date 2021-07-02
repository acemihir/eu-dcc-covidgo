FROM ruby:3.0.1
RUN apt-get update -qq && apt-get install -y build-essential libpq-dev

RUN mkdir /app
WORKDIR /app

# ENV RAILS_ENV development

COPY Gemfile /app/Gemfile
COPY Gemfile.lock /app/Gemfile.lock
RUN bundle install

COPY . /app

# Add a script to be executed every time the container starts.
# COPY entrypoint.sh /usr/bin/
# RUN chmod +x /usr/bin/entrypoint.sh
# ENTRYPOINT ["entrypoint.sh"]

EXPOSE 3000
# Configure the main process to run when running the image
CMD ["rails", "server", "-b", "0.0.0.0"]