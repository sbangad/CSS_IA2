package mashdump;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Vector;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

public class Mashdump
{
    public static void main(String[] args)throws IOException
    {
        System.out.print("Option selected: ");
        for(int i=0;i<args.length;i++)
            System.out.print(args[i]+" ");
        System.out.println("\n");
        File f;
        if(args.length==4)
        {
            f=new File(args[3]);
            f.createNewFile();
        }
        Vector<PcapIf> interfaces=new Vector<PcapIf>();
        StringBuilder error=new StringBuilder();
        int x=Pcap.findAllDevs(interfaces,error);
        if(args.length>=1&&args[0].trim().equals("-D"))
        {
            if(x==Pcap.NOT_OK||interfaces.isEmpty())
                System.out.println("No interfaces present! Error: "+error.toString());
            else
            {
                for(int i=0;i<interfaces.size();i++)
                {
                    System.out.println((i+1)+": "+interfaces.get(i).toString());
                }
            }
        }
        else if(args.length>=2&&args[0].trim().equals("-i"))
        {
            final boolean a;
            if(args.length==2)
                a=false;
            else
                a=true;
            int num=Integer.parseInt(args[1])-1;
            PcapIf interf=interfaces.get(num);
            int len=64*1024;
            int flags=Pcap.MODE_PROMISCUOUS;
            int timeout=10*100;
            Pcap pc=Pcap.openLive(interf.getName(),len,flags,timeout,error);
            if(pc==null)
            {
                System.out.println("Some error!");
            }
            else
            {
                PcapPacketHandler<String> packetHandler=new PcapPacketHandler<String>(){
                    @Override
                    public void nextPacket(PcapPacket packet,String user)
                    {
                        byte[] data=packet.getByteArray(0,packet.size());
                        if(!a)
                        {
                            System.out.println("\n\nPacket :"+packet.toString()+" caplen="+packet.getCaptureHeader().caplen());
                            //f.delete();
                        }
                        else
                        {
                            if((!args[2].equals("-f"))||args.length==3)
                            {
                                System.out.println("Wrong command!");
                                //f.delete();
                            }
                            else
                            {
                                try
                                {
                                    BufferedWriter fw=new BufferedWriter(new FileWriter(args[3],true));
                                    fw.write("\n\nPacket :"+packet.toString()+" caplen="+packet.getCaptureHeader().caplen());
                                    fw.close();
                                }
                                catch(Exception e)
                                {
                                    //f.delete();
                                    System.out.println(e);
                                }
                            }
                        }
                    }
                };
                pc.loop(10,packetHandler,"jNetPcap");
                pc.close();
            }
            if(args.length==4)
                System.out.println("Packets saved to the file");
        }
        else if(args.length>=2&&args[0].trim().equals("-f"))
        {
            try
            {
                BufferedReader fr=new BufferedReader(new FileReader(args[1]));
                String s;
                while((s=fr.readLine())!=null)
                    System.out.println(s);
            }
            catch(Exception e)
            {
                System.out.println(e);
            }
        }
        else if(args.length==3&&args[0].trim().equals("ip")&&args[1].trim().equals("-i"))
        {
            int num=Integer.parseInt(args[2])-1;
            PcapIf interf=interfaces.get(num);
            int len=64*1024;
            int flags=Pcap.MODE_PROMISCUOUS;
            int timeout=10*100;
            Pcap pc=Pcap.openLive(interf.getName(),len,flags,timeout,error);
            if(pc==null)
            {
                System.out.println("Some error!");
            }
            else
            {
                PcapPacketHandler<String> packetHandler=new PcapPacketHandler<String>(){
                    @Override
                    public void nextPacket(PcapPacket packet,String user)
                    {
                        byte[] data=packet.getByteArray(0,packet.size());
                        byte[] sIP=new byte[4];
                        byte[] dIP=new byte[4];
                        Ip4 ip=new Ip4();
                        if(!packet.hasHeader(ip))
                            return;
                        sIP=ip.source();
                        dIP=ip.destination();
                        System.out.println("Source: "+org.jnetpcap.packet.format.FormatUtils.ip(sIP)+" Destination: "+org.jnetpcap.packet.format.FormatUtils.ip(dIP)+" caplen="+packet.getCaptureHeader().caplen());
                    }
                };
                pc.loop(10,packetHandler,"jNetPcap");
                pc.close();
            }
        }
        else if(args.length==3&&args[0].trim().equals("tcp")&&args[1].trim().equals("-i"))
        {
            int num=Integer.parseInt(args[2])-1;
            PcapIf interf=interfaces.get(num);
            int len=64*1024;
            int flags=Pcap.MODE_PROMISCUOUS;
            int timeout=10*100;
            Pcap pc=Pcap.openLive(interf.getName(),len,flags,timeout,error);
            if(pc==null)
            {
                System.out.println("Some error!");
            }
            else
            {
                PcapPacketHandler<String> packetHandler=new PcapPacketHandler<String>(){
                    @Override
                    public void nextPacket(PcapPacket packet,String user)
                    {
                        byte[] data=packet.getByteArray(0,packet.size());
                        int sPort,dPort;
                        Tcp tcp=new Tcp();
                        if(!packet.hasHeader(tcp))
                            return;
                        sPort=tcp.source();
                        dPort=tcp.destination();
                        System.out.println("Source: "+sPort+" Destination: "+dPort+" caplen="+packet.getCaptureHeader().caplen());
                    }
                };
                pc.loop(10,packetHandler,"jNetPcap");
                pc.close();
            }
        }
    }
}