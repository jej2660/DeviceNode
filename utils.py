def toList(object):
    ls = []
    for o in object:
        ls.append(o)
    return ls

def toString(object):
    string = ""
    count = 0
    length = len(object) - 1
    for o in object:
        if count == length:
            string += o
        string += o + "->"
        count += 1
    return string
        
        