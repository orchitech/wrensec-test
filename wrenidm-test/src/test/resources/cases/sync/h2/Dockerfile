FROM eclipse-temurin:17
RUN \
  mkdir /h2 && \
  cd /h2 && \
  curl -s https://repo1.maven.org/maven2/com/h2database/h2/2.2.224/h2-2.2.224.jar  --output h2.jar
COPY entrypoint.sh /h2/
COPY schema.sql /h2/
ENTRYPOINT [ "/h2/entrypoint.sh" ]
