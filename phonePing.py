import subprocess

fileName = input("Name of run: ")
dis = input("Distance: ")
p = subprocess.Popen(["ping","-c180","-i", ".5","-D", "ip_of_router"],stdout=subprocess.PIPE, stderr=subprocess.PIPE)
output = p.stdout.read().decode('utf-8')
for line in output.splitlines():
    if "time=" in line:
        #print(line)
        with open(fileName+'.csv','a',newline='') as f:
            f.write("distance= "+dis+" timestamp= "+ line.split(":")[0].split("]")[0][1:]+ line.split(":")[1]+'\n')