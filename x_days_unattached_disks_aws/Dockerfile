FROM python:3.9-slim-buster
WORKDIR /usr/src/app
COPY . .
RUN python3 -m pip install -r requirements.txt
CMD ["x_days_list_unattached_disks.py"]
ENTRYPOINT ["python3"]

