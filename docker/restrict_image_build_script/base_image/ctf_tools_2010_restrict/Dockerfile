FROM ubuntu:20.10

ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN sed -i "s/http:\/\/archive.ubuntu.com/http:\/\/mirrors.ustc.edu.cn/g" /etc/apt/sources.list && \
    sed -i "s/http:\/\/security.ubuntu.com/http:\/\/mirrors.ustc.edu.cn/g" /etc/apt/sources.list && \
    sed -i "s/# deb-src/ deb-src/g" /etc/apt/sources.list && \
    apt-get update && apt-get -y dist-upgrade && apt-get update &&\
    apt-get install -y lib32z1 xinetd tmux strace tcpdump libssl-dev locales  python2 curl libpython2-dev libgmp-dev libmpfr-dev libmpc-dev binutils dpkg-dev build-essential

COPY common/setup_libc_debug.sh /opt

RUN chmod +x /opt/setup_libc_debug.sh && /opt/setup_libc_debug.sh

RUN sed -i -e 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen && \
    locale-gen
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8

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

RUN python3 -m pip install -i https://mirrors.aliyun.com/pypi/simple pip -U && python3 -m pip config set global.index-url https://mirrors.aliyun.com/pypi/simple

RUN python3 -m pip install setuptools --upgrade

RUN python3 -m pip install pwntools requests capstone keystone-engine unicorn keystone-engine ropper

RUN curl https://bootstrap.pypa.io/get-pip.py --output get-pip.py

RUN python2 get-pip.py

RUN python2 -m pip  install --upgrade pip

RUN python2 -m pip  install setuptools --upgrade

RUN python2 -m pip install pwntools requests capstone keystone-engine unicorn keystone-engine ropper

RUN mkdir /var/run/sshd

COPY common/gef.py /root/.gdbinit-gef.py

RUN echo source ~/.gdbinit-gef.py >> ~/.gdbinit

RUN mkdir /root/raw
RUN mkdir /root/local_verify_success
RUN mkdir /root/local_verify_failed
RUN mkdir /root/remote_verify_success
RUN mkdir /root/remote_verify_failed



WORKDIR /opt

RUN apt-get install -y wget bison flex build-essential unzip \
    && apt-get build-dep -y xinetd

COPY common/kafel-master.zip /opt/master.zip

RUN unzip master.zip && rm master.zip && mv kafel-master kafel && cd kafel && make

COPY common/xinetd-kafel-master.zip /opt/master.zip

RUN unzip master.zip && rm master.zip && mv xinetd-kafel-master xinetd && cd xinetd && ./configure --prefix=/usr --with-kafel=/opt/kafel --with-loadavg --with-libwrap && make

RUN apt-get update && apt-get install -y --no-install-recommends wget netbase tcpdump xinetd && \
    apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /etc/xinetd.d/*

RUN cp -f /opt/xinetd/xinetd/xinetd /usr/sbin/xinetd

ADD common/xinetd.conf /etc/xinetd.conf
ADD common/pwn.kafel /etc/pwn.kafel
ADD common/banner_fail /etc/banner_fail
RUN mkdir -p /etc/service/xinetd
ADD common/xinetd.sh /etc/service/xinetd/run
RUN chmod +x /etc/service/xinetd/run
ADD common/ctf.xinetd.example /etc/xinetd.d/ctf
ADD common/xinetd.sh /root/



CMD ["/usr/sbin/sshd -D"]