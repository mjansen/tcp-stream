{-# LANGUAGE OverloadedStrings #-}

module TCPDumpParser1 (parseFile, TCPPacket(..), showText) where

-- parse the output of tcpdump -ttnnr file

import Data.Int
import System.Environment
import Data.Maybe
import Text.Printf
import qualified Data.ByteString.Char8            as B
import qualified Data.Attoparsec.ByteString.Char8 as P

parseFile fName = do
  content <- B.readFile fName
  case P.parseOnly parseFileContent content of
    Left eMessage -> print eMessage >> return []
    Right rs      -> return rs

-- | A byte range
    
data Interval = Interval Integer Integer
              deriving (Eq, Ord, Show, Read)

-- | A TCP end-point

newtype EndPoint = EndPoint Int64
                 deriving (Eq, Ord, Show, Read)

data SeqInfo = Seq_None | Seq_Start !Integer | Seq_Interval !Interval
             deriving (Eq, Ord, Show, Read)

data TCPPacket = TCPPacket
  { timeStamp         :: !Double
  , src               :: !EndPoint
  , dst               :: !EndPoint
  , flags             :: B.ByteString
  , seq               :: SeqInfo
  , haveInterval      :: Interval
  , windowSize        :: !Integer
  , alsoHaveIntervals :: [Interval]
  , packetLength      :: !Int
  } deriving (Eq, Ord, Show, Read)

showText :: Double -> TCPPacket -> String
showText startTS (TCPPacket ts src dst flags seq (Interval a b) ws ahs len) = printf "%17.6f %10d %10d: %s" (ts - startTS) b ws (showIntervals . rebase b $ ahs)

rebase x0 rs = map (\(Interval x1 x2) -> Interval (x1 - x0) (x2 - x0)) rs

showIntervals :: [Interval] -> String
showIntervals rs = concat $ map (\(Interval a b) -> printf "    (%6d, %6d)" a (b - a)) rs

parseLine :: P.Parser (Maybe TCPPacket)
parseLine = P.choice [ fmap Just $ P.try parsePacketLine, skipToNextLine >> return Nothing ]

parseSeq :: P.Parser SeqInfo
parseSeq = P.choice [ P.try parseSeq', return Seq_None ]
  where
    parseSeq' = do
      P.string ", seq "
      a <- P.decimal
      P.choice [ P.try (P.char ':' >> P.decimal >>= (\b -> return (Seq_Interval $ Interval a b))), return $ Seq_Start a ]

parseEndPoint :: P.Parser EndPoint
parseEndPoint = do
  a <- P.decimal
  P.char '.'
  b <- P.decimal
  P.char '.'
  c <- P.decimal
  P.char '.'
  d <- P.decimal
  P.char '.'
  e <- P.decimal
  return $ EndPoint (((((a*256) + b)*256 + c)*256 +d)*256*256 + e)

parsePacketLine :: P.Parser TCPPacket
parsePacketLine = do
  ts <- P.double
  P.string " IP "
  srcAddr <- parseEndPoint
  P.string " > "
  dstAddr <- parseEndPoint
  P.string ": Flags ["
  flags <- P.takeWhile (\c -> c /= ']' && c /= '\n')
  P.string "]"
  seq <- parseSeq
  ack <- P.choice [ P.try (P.string (", ack ") >> P.decimal), return 0 ]
  P.string ", win "
  ws <- P.decimal
  P.string ", "
  os <- fmap concat $ parseOptions
  P.string ", length "
  len <- P.decimal
  skipToNextLine
  return $ TCPPacket ts srcAddr dstAddr flags seq (Interval 0 ack) ws os len

parseFileContent :: P.Parser [Maybe TCPPacket]
parseFileContent = P.many1 parseLine

skipToNextLine :: P.Parser ()
skipToNextLine = do
  _ <- P.takeWhile (/= '\n')
  _ <- P.char '\n'
  return ()

parseSackBlock :: P.Parser Interval
parseSackBlock = do
  P.char '{'
  start <- P.decimal
  P.char ':'
  finish <- P.decimal
  P.char '}'
  return $ Interval start finish

parseSack :: P.Parser [Interval]
parseSack = do
  P.string "sack "
  n <- P.decimal
  P.char ' '
  xs <- P.count n parseSackBlock
  return xs

parseOptions :: P.Parser [[Interval]]
parseOptions = do
  P.string "options ["
  rs <- P.sepBy parseOption (P.char ',')
  P.char ']'
  return rs

parseOption = P.choice [ P.try (P.string "nop") >> return []
                       -- , P.try parseTS
                       , P.try parseSack
                       , P.takeWhile (\c -> (c /= ']') && c /= ',') >> return []
                       ]
