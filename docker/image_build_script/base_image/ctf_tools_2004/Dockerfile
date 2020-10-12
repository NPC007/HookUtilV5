FROM ubuntu:20.04

ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN sed -i "s/http:\/\/archive.ubuntu.com/http:\/\/mirrors.tuna.tsinghua.edu.cn/g" /etc/apt/sources.list && \
    apt-get update && apt-get -y dist-upgrade && apt-get update &&\
    apt-get install -y lib32z1 xinetd tmux strace tcpdump libssl-dev

RUN useradd -m ctf

WORKDIR /home/ctf

RUN cp -RfL /lib* /home/ctf && \
    cp -RfL /usr/lib* /home/ctf

RUN mkdir -p /home/ctf/usr/lib/
RUN cp -R /usr/lib* /home/ctf/usr/

RUN mkdir /home/ctf/dev && \
    mknod /home/ctf/dev/null c 1 3 && \
    mknod /home/ctf/dev/zero c 1 5 && \
    mknod /home/ctf/dev/random c 1 8 && \
    mknod /home/ctf/dev/urandom c 1 9 && \
    chmod 666 /home/ctf/dev/*

RUN mkdir /home/ctf/bin && \
    cp /bin/sh /home/ctf/bin && \
    cp /bin/ls /home/ctf/bin && \
    cp /bin/cat /home/ctf/bin

RUN  mkdir -p /home/ctf/tmp
RUN  chmod 777 /home/ctf/tmp -R

RUN chown -R root:ctf /home/ctf && \
    chmod -R 750 /home/ctf

RUN apt-get install openssh-server git python gcc python3-pip vim net-tools lsof gdb psmisc netcat -y

RUN python3 -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple pip -U && python3 -m pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple

RUN python3 -m pip install setuptools --upgrade

RUN python3 -m pip install pwntools requests capstone keystone-engine unicorn keystone-engine ropper

RUN mkdir /var/run/sshd

COPY common/gef.py /root/.gdbinit-gef.py

RUN echo source ~/.gdbinit-gef.py >> ~/.gdbinit

RUN mkdir /root/raw
RUN mkdir /root/local_verify_success
RUN mkdir /root/local_verify_failed
RUN mkdir /root/remote_verify_success
RUN mkdir /root/remote_verify_failed

CMD ["/usr/sbin/sshd -D"]