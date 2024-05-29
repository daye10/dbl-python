
# Create a file named Makefile.local to override the variables below
ANDROID_JAR=$(ANDROID_HOME)/platforms/android-29/android.jar
DX=$(ANDROID_HOME)/build-tools/30.0.3/dx

-include Makefile.local

all: getCurrency.dex

getCurrency.class: getCurrency.java
	javac -source 1.7 -target 1.7 -cp $(ANDROID_JAR) getCurrency.java

getCurrency.dex: getCurrency.class
	$(DX) --dex --output getCurrency.dex getCurrency.class
