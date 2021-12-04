FROM ruby:3.0.2
RUN apt-get update -qq && apt-get install -y build-essential libpq-dev

RUN mkdir /app
WORKDIR /app

ENV RAILS_ENV production
ENV RAILS_SERVE_STATIC_FILES true

COPY Gemfile /app/Gemfile
COPY Gemfile.lock /app/Gemfile.lock

RUN bundle config set --local without 'development test'
RUN bundle config --global frozen 1
RUN bundle install

COPY . /app

EXPOSE 3000
# Configure the main process to run when running the image
CMD ["rails", "server", "-b", "0.0.0.0"]