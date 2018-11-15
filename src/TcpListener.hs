{-# LANGUAGE RecordWildCards, ScopedTypeVariables #-}
module TcpListener where
import Network.Pcap as P
import qualified Net.Packet as Packet
import qualified Net.PacketParsing as PacketParsing
import Foreign.Marshal.Array
import Data.Array.IArray
import Net.IPv4 as IPv4
import Net.TCP as TCP
import Net.Ethernet as Ethernet
import Data.Word
import Data.Array.Unboxed
import Foreign.Ptr
import Control.Monad (void)
import Text.Printf
import Data.List

data EventHandlers = EventHandlers
  { syn    :: IO ()
  , rst    :: IO ()
  , synAck :: IO ()
  }

defaultEventHandlers :: EventHandlers
defaultEventHandlers = EventHandlers
  { syn    = print "SYN Sent"
  , rst    = print "RST Sent"
  , synAck = print "SYN/ACK Sent"
  }

makeUArray :: Int -> Ptr Word8 -> IO (UArray Int Word8)
makeUArray count ptr = do
  bytes <- drop 4 <$> peekArray count ptr

  pure $ array (0, length bytes - 1) (zip [0..] bytes)

handleTCPPacket :: EventHandlers -> TCP.Packet a -> IO ()
handleTCPPacket EventHandlers {..} TCP.Packet {..} = case controlBits of
  TCP.CB { syn = True, ack = True } -> synAck
  TCP.CB { syn = True }             -> syn
  TCP.CB { rst = True }             -> rst

watch :: EventHandlers -> Int -> IO ()
watch eh port = do
  -- HACK to get the loopback interface
  [interface] <- filter (("lo" `isPrefixOf`) . P.ifName) <$> findAllDevs
  -- start a live handle
  handle <- P.openLive (P.ifName interface) 1024 False 10000000
  P.setNonBlock handle True
  -- filter the traffic by the deviceName and port
  setFilter handle ("tcp port " ++ show port) False 0xff000000

  void $ P.loop handle (-1) $ \pktHdr bytes -> do
    chunk <- makeUArray (fromIntegral $ hdrCaptureLength pktHdr) bytes

    case PacketParsing.doParse $ Packet.toInPack chunk of
      Nothing -> putStrLn "Parsing failure"
      Just (packet :: IPv4.Packet (TCP.Packet (UArray Int Word8))) -> do
        print packet
        handleTCPPacket eh $ IPv4.content packet

