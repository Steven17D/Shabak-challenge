import binascii
import operator


class EncryptionStepDescriptor(object):
    def __init__(self, operationCode, operationParameter, lengthToOperateOn):
        self.operationCode = int(operationCode)
        self.operationParameter = int(operationParameter, 16)
        self.lengthToOperateOn = int(lengthToOperateOn[:2], 16)


def lengthToOperateOn_sum(x, y):
    if type(x) is int:
        return x + y.lengthToOperateOn
    return x.lengthToOperateOn + y.lengthToOperateOn


def apply_operation(operation, parameter):
    assert apply_operation.data is not None

    original_value = apply_operation.data[apply_operation.position]
    apply_operation.data[apply_operation.position] = abs(operation(original_value, parameter)) % 256

    if apply_operation.position + apply_operation.direction == len(apply_operation.data) \
            or apply_operation.position + apply_operation.direction == -1:
        apply_operation.direction *= -1
    else:
        apply_operation.position += apply_operation.direction


def main():
    key = []
    apply_operation.position = 0
    apply_operation.direction = 1
    with open('Key.bin', 'rb') as key_file:
        key_data = binascii.hexlify(key_file.read())
        struct_size = (8 + 8 + 32) / 4
        for struct in [key_data[i:i + struct_size] for i in range(0, len(key_data), struct_size)]:
            operationCode = struct[:2]
            operationParameter = struct[2:4]
            lengthToOperateOn = struct[4:]
            key.append(EncryptionStepDescriptor(operationCode, operationParameter, lengthToOperateOn))

    with open('EncryptedMessage.bin', 'rb') as message_file:
        encrypted_message = binascii.hexlify(message_file.read())
        encrypted_message = map(lambda x: int(x, 16),
                                [encrypted_message[i:i + 2] for i in range(0, len(encrypted_message), 2)])
        apply_operation.data = encrypted_message
        print "Message length:", len(encrypted_message)

    print "Key total length:", reduce(lengthToOperateOn_sum, key)
    for step in key:
        print "Key:\t", step.operationCode, step.operationParameter, step.lengthToOperateOn
        if step.operationCode == 0:  # Xor
            operation = operator.xor
        elif step.operationCode == 1:  # Add
            operation = operator.add
        elif step.operationCode == 2:  # Subtract
            operation = operator.sub

        [apply_operation(operation, step.operationParameter) for _ in xrange(step.lengthToOperateOn)]
    print "Output:\n", ''.join(map(lambda x: chr(x), apply_operation.data))


if __name__ == '__main__':
    main()
