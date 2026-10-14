"""从聊天记录生成词云图"""

import argparse
from collections import Counter
from itertools import chain
from pprint import pprint

from ntqq import QQNT, Group
from ntqq.message import Text

# import hanlp
import wordcloud


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--contact", type=int)
    args = parser.parse_args()

    qq = QQNT.open("./work/plain")

    contact = qq.contact(args.contact)
    if contact is None:
        qq.close()
        print(f"contact not found: {args.contact}")
        return 0

    names = qq.member_names(contact) if isinstance(contact, Group) else []

    # HanLP = hanlp.load(hanlp.pretrained.tok.COARSE_ELECTRA_SMALL_ZH)

    messages = []

    for message in qq.messages(chat=contact):
        for element in message.elements:
            if element.type_name == "text":
                assert isinstance(element, Text)
                plain = element.plain(names)
                messages.append(plain + "\n")

    # toks = HanLP(messages)

    # counter = Counter(chain.from_iterable(toks))
    
    with open("messages.txt", "w") as f:
        f.writelines(messages)

    qq.close()


if __name__ == "__main__":
    raise SystemExit(main())
